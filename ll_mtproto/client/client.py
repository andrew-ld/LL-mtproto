# Copyright (C) 2017-2018 (nikat) https://github.com/nikat/mtproto2json
# Copyright (C) 2020-2023 (andrew) https://github.com/andrew-ld/LL-mtproto

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import asyncio
import concurrent.futures
import logging
import traceback
import typing

from ll_mtproto.client.connection_info import ConnectionInfo
from ll_mtproto.client.error_description_resolver.base_error_description_resolver import BaseErrorDescriptionResolver
from ll_mtproto.client.pending_request import PendingRequest
from ll_mtproto.client.rpc_error import RpcError
from ll_mtproto.client.update import Update
from ll_mtproto.crypto.auth_key import AuthKey, Key
from ll_mtproto.crypto.providers.crypto_provider_base import CryptoProviderBase
from ll_mtproto.network.auth_key_not_found_exception import AuthKeyNotFoundException
from ll_mtproto.network.datacenter_info import DatacenterInfo
from ll_mtproto.network.dispatcher import Dispatcher, dispatch_event
from ll_mtproto.network.mtproto import MTProto
from ll_mtproto.network.mtproto_key_exchange import MTProtoKeyExchange
from ll_mtproto.network.transport.transport_link_factory import TransportLinkFactory
from ll_mtproto.tl.byteutils import reader_discard, to_reader
from ll_mtproto.tl.structure import Structure, StructureBody
from ll_mtproto.tl.tl import TlBodyData, Constructor

__all__ = ("Client",)


class _ClientDispatcher(Dispatcher):
    __slots__ = ("_impl",)

    _impl: "Client"

    def __init__(self, impl: "Client"):
        self._impl = impl

    async def process_telegram_message_body(self, body: Structure, crypto_flag: bool) -> None:
        assert crypto_flag
        await self._impl._process_telegram_message_body(body)

    async def process_telegram_signaling_message(self, signaling: Structure, crypto_flag: bool) -> None:
        assert crypto_flag
        self._impl._process_telegram_signaling_message(signaling)


class Client:
    __slots__ = (
        "_mtproto",
        "_loop",
        "_msgids_to_ack",
        "_mtproto_loop_task",
        "_pending_requests",
        "_pending_pong",
        "_datacenter",
        "_pending_ping",
        "_updates_queue",
        "_no_updates",
        "_pending_future_salt",
        "_layer_init_info",
        "_layer_init_required",
        "_auth_key_lock",
        "_use_perfect_forward_secrecy",
        "_blocking_executor",
        "_write_queue",
        "_used_session_key",
        "_persistent_session_key",
        "_rpc_error_constructor",
        "_dispatcher",
        "_crypto_provider",
        "_error_description_resolver"
    )

    _mtproto: MTProto
    _loop: asyncio.AbstractEventLoop
    _msgids_to_ack: list[int]
    _mtproto_loop_task: asyncio.Task[None] | None
    _pending_requests: dict[int, PendingRequest]
    _pending_pong: asyncio.TimerHandle | None
    _datacenter: DatacenterInfo
    _pending_ping: asyncio.TimerHandle | asyncio.Task[None] | None
    _updates_queue: asyncio.Queue[Update | None]
    _no_updates: bool
    _pending_future_salt: asyncio.TimerHandle | asyncio.Task[None] | None
    _layer_init_info: ConnectionInfo
    _layer_init_required: bool
    _auth_key_lock: asyncio.Lock
    _use_perfect_forward_secrecy: bool
    _blocking_executor: concurrent.futures.Executor
    _write_queue: asyncio.Queue[PendingRequest]
    _used_session_key: Key
    _persistent_session_key: Key
    _rpc_error_constructor: Constructor
    _dispatcher: _ClientDispatcher
    _crypto_provider: CryptoProviderBase
    _error_description_resolver: BaseErrorDescriptionResolver | None

    def __init__(
            self,
            datacenter: DatacenterInfo,
            auth_key: AuthKey,
            connection_info: ConnectionInfo,
            transport_link_factory: TransportLinkFactory,
            blocking_executor: concurrent.futures.Executor,
            crypto_provider: CryptoProviderBase,
            no_updates: bool = True,
            use_perfect_forward_secrecy: bool = False,
            error_description_resolver: BaseErrorDescriptionResolver | None = None
    ):
        self._datacenter = datacenter
        self._layer_init_info = connection_info
        self._no_updates = no_updates
        self._use_perfect_forward_secrecy = use_perfect_forward_secrecy
        self._blocking_executor = blocking_executor
        self._crypto_provider = crypto_provider
        self._error_description_resolver = error_description_resolver

        rpc_error_constructor = datacenter.schema.constructors.get("rpc_error", None)

        if rpc_error_constructor is None:
            raise TypeError(f"Unable to find rpc_error constructor")

        self._rpc_error_constructor = rpc_error_constructor

        self._loop = asyncio.get_running_loop()
        self._auth_key_lock = asyncio.Lock()

        self._msgids_to_ack = list()
        self._pending_requests = dict()
        self._layer_init_required = True

        self._pending_pong = None
        self._pending_ping = None
        self._pending_future_salt = None

        self._mtproto_loop_task = None
        self._updates_queue = asyncio.Queue()
        self._write_queue = asyncio.Queue()
        self._dispatcher = _ClientDispatcher(self)

        self._mtproto = MTProto(datacenter, transport_link_factory, self._in_thread, crypto_provider)

        self._used_session_key = auth_key.temporary_key if use_perfect_forward_secrecy else auth_key.persistent_key
        self._persistent_session_key = auth_key.persistent_key

    async def _in_thread(self, *args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        return await self._loop.run_in_executor(self._blocking_executor, *args, **kwargs)

    async def get_update(self) -> Update | None:
        if self._no_updates:
            raise RuntimeError("the updates queue is always empty if no_updates has been set to true.")

        await self._start_mtproto_loop_if_needed()
        return await self._updates_queue.get()

    async def rpc_call(self, payload: TlBodyData) -> StructureBody:
        pending_request = PendingRequest(
            response=self._loop.create_future(),
            message=payload,
            seq_no_func=self._used_session_key.get_next_odd_seqno,
            allow_container=True,
            expect_answer=True
        )

        pending_request.cleaner = self._loop.call_later(120, lambda: pending_request.finalize())

        await self._start_mtproto_loop_if_needed()
        await self._rpc_call(pending_request)

        return await pending_request.response

    async def _rpc_call(self, request: PendingRequest) -> None:
        self._ensure_mtproto_loop()
        await self._write_queue.put(request)

    def _wrap_request_in_layer_init(self, message: TlBodyData) -> TlBodyData:
        message = dict(_cons="initConnection", _wrapped=message, **self._layer_init_info.to_request_body())
        message = dict(_cons="invokeWithLayer", _wrapped=message, layer=self._datacenter.schema.layer)

        if self._no_updates:
            message = dict(_cons="invokeWithoutUpdates", _wrapped=message)

        return message

    async def _start_mtproto_loop(self) -> None:
        self.disconnect()

        logging.debug("connecting to Telegram at %s", self._datacenter)
        self._mtproto_loop_task = self._loop.create_task(self._mtproto_loop())

        await self._create_init_requests()

    async def _create_init_requests(self) -> None:
        await self._create_future_salt_request()
        await self._create_ping_request()

    async def _create_destroy_session_request(self, destroyed_session_id: int) -> None:
        destroy_session_message: TlBodyData = dict(_cons="destroy_session", session_id=destroyed_session_id)

        destroy_session_request = PendingRequest(
            response=self._loop.create_future(),
            message=destroy_session_message,
            seq_no_func=self._used_session_key.get_next_odd_seqno,
            allow_container=False,
            expect_answer=True
        )

        await self._rpc_call(destroy_session_request)

    async def _create_future_salt_request(self) -> None:
        get_future_salts_message: TlBodyData = dict(_cons="get_future_salts", num=32)

        get_future_salts_request = PendingRequest(
            response=self._loop.create_future(),
            message=get_future_salts_message,
            seq_no_func=self._used_session_key.get_next_odd_seqno,
            allow_container=False,
            expect_answer=True
        )

        if pending_future_salt := self._pending_future_salt:
            pending_future_salt.cancel()

        def _initialize_future_salt_request() -> None:
            if pending_future_salt := self._pending_future_salt:
                pending_future_salt.cancel()

            self._pending_future_salt = self._loop.create_task(self._create_future_salt_request())

        self._pending_future_salt = self._loop.call_later(30, _initialize_future_salt_request)

        await self._rpc_call(get_future_salts_request)

    async def _create_ping_request(self) -> None:
        self._used_session_key.session.ping_id += 1
        ping_id = self._used_session_key.session.ping_id

        if pending_pong := self._pending_pong:
            pending_pong.cancel()

        self._pending_pong = self._loop.call_later(20, self.disconnect)

        ping_message: TlBodyData = dict(_cons="ping_delay_disconnect", ping_id=ping_id, disconnect_delay=35)

        ping_request = PendingRequest(
            response=self._loop.create_future(),
            message=ping_message,
            seq_no_func=self._used_session_key.get_next_odd_seqno,
            allow_container=False,
            expect_answer=True
        )

        await self._rpc_call(ping_request)

    def _cancel_pending_request(self, msg_id: int) -> None:
        if pending_request := self._pending_requests.pop(msg_id, None):
            pending_request.finalize()

    async def _start_auth_key_exchange_if_needed(self) -> None:
        self._ensure_mtproto_loop()

        async with self._auth_key_lock:
            if (perm_auth_key := self._persistent_session_key).is_empty():
                exchanger = MTProtoKeyExchange(self._mtproto, self._in_thread, self._datacenter, self._crypto_provider, self._dispatcher, None)
                generated_key = await exchanger.generate_key()
                perm_auth_key.import_dh_gen_key(generated_key)

            if self._use_perfect_forward_secrecy and (temp_auth_key := self._used_session_key).is_empty():
                exchanger = MTProtoKeyExchange(self._mtproto, self._in_thread, self._datacenter, self._crypto_provider, self._dispatcher, self._persistent_session_key)
                generated_key = await exchanger.generate_key()
                temp_auth_key.import_dh_gen_key(generated_key)

    async def _process_outbound_message(self, message: PendingRequest) -> None:
        message.retries += 1

        if message.response.done():
            return logging.warning("request %r already completed", message.request)

        if cleaner := message.cleaner:
            cleaner.cancel()

        if message.allow_container:
            layer_init_boxing_required = self._layer_init_required
        else:
            layer_init_boxing_required = False

        request_body = message.request

        if layer_init_boxing_required:
            request_body = self._wrap_request_in_layer_init(request_body)

        try:
            boxed_message, boxed_message_id = self._mtproto.prepare_message_for_write(message.next_seq_no(), request_body)
        except Exception as serialization_exception:
            message.response.set_exception(serialization_exception)
            message.finalize()
            return

        if message.expect_answer:
            self._pending_requests[boxed_message_id] = message
            message.cleaner = self._loop.call_later(120, self._cancel_pending_request, boxed_message_id)

        logging.debug("writing message %d (%s)", boxed_message_id, message.request["_cons"])

        await self._mtproto.write_encrypted(boxed_message, self._used_session_key)

    async def _mtproto_write_loop(self) -> None:
        while True:
            await self._process_outbound_message(await self._write_queue.get())

    async def _mtproto_read_loop(self) -> None:
        while True:
            await dispatch_event(self._dispatcher, self._mtproto, self._used_session_key)
            await self._flush_msgids_to_ack()

    async def _mtproto_loop(self) -> None:
        try:
            await self._start_auth_key_exchange_if_needed()
        except (KeyboardInterrupt, asyncio.CancelledError, GeneratorExit):
            raise
        except:
            logging.debug("unable to generate mtproto auth key: %s", traceback.format_exc())
            self.disconnect()
            raise asyncio.CancelledError()

        self._used_session_key.generate_new_unique_session_id()
        self._used_session_key.flush_changes()

        read_task = self._loop.create_task(self._mtproto_read_loop())
        write_task = self._loop.create_task(self._mtproto_write_loop())

        for unused_session in self._used_session_key.unused_sessions:
            await self._create_destroy_session_request(unused_session)

        try:
            await asyncio.gather(write_task, read_task)
        except (KeyboardInterrupt, asyncio.CancelledError, GeneratorExit):
            raise
        except AuthKeyNotFoundException:
            auth_key_id = self._used_session_key.auth_key_id

            if self._use_perfect_forward_secrecy and (not self._used_session_key.is_fresh_key()):
                self._used_session_key.clear_key()
                self._used_session_key.flush_changes()

            logging.error("auth key id `%r` not found, retry connection", auth_key_id)
        except:
            logging.error("unable to process message in consumer: %s", traceback.format_exc())
        finally:
            write_task.cancel()
            read_task.cancel()

        self.disconnect()
        raise asyncio.CancelledError()

    def _ensure_mtproto_loop(self) -> None:
        if mtproto_loop_task := self._mtproto_loop_task:
            if mtproto_loop_task.done():
                raise asyncio.InvalidStateError("mtproto loop closed")
        else:
            raise asyncio.InvalidStateError("mtproto loop closed")

    async def _start_mtproto_loop_if_needed(self) -> None:
        if mtproto_loop_task := self._mtproto_loop_task:
            if mtproto_loop_task.done():
                await self._start_mtproto_loop()
        else:
            await self._start_mtproto_loop()

    async def _process_telegram_message_body(self, body: Structure) -> None:
        match (constructor_name := body.constructor_name):
            case "rpc_result":
                await self._process_rpc_result(body)

            case "updates":
                await self._process_updates(body)

            case "updatesCombined":
                await self._process_updates(body)

            case "updateShort":
                await self._process_update_short(body)

            case "updateShortMessage":
                await self._process_update_short_message(body)

            case "updateShortChatMessage":
                await self._process_update_short_message(body)

            case "updateShortSentMessage":
                await self._process_update_short_message(body)

            case "bad_server_salt":
                await self._process_bad_server_salt(body)

            case "bad_msg_notification":
                await self._process_bad_msg_notification(body)

            case "new_session_created":
                await self._process_new_session_created(body)

            case "pong":
                self._process_pong(body)

            case "future_salts":
                self._process_future_salts(body)

            case "msg_detailed_info":
                self._process_msg_detailed_info(body)

            case "msg_new_detailed_info":
                self._process_msg_new_detailed_info(body)

            case "msgs_state_info":
                self._process_msgs_state_info(body)

            case "msgs_ack":
                self._process_msgs_ack(body)

            case "destroy_session_ok" | "destroy_session_none":
                self._process_session_destroy(body)

            case _:
                logging.critical("unknown message type (%s) received", constructor_name)

    def _process_session_destroy(self, body: Structure) -> None:
        logging.debug("session destroy received: %s", body.constructor_name)
        self._used_session_key.unused_sessions.remove(body.session_id)
        self._used_session_key.flush_changes()

    async def _process_update_short_message(self, body: Structure) -> None:
        if not self._no_updates:
            await self._updates_queue.put(Update([], [], body))

    async def _process_update_short(self, body: Structure) -> None:
        if not self._no_updates:
            await self._updates_queue.put(Update([], [], body.update))

    def _process_msgs_ack(self, body: Structure) -> None:
        logging.debug("received msgs_ack %r", body.msg_ids)

    def _process_msgs_state_info(self, body: Structure) -> None:
        if pending_request := self._pending_requests.pop(body.req_msg_id, None):
            pending_request.response.set_result(body)
            pending_request.finalize()

    def _process_msg_new_detailed_info(self, body: Structure) -> None:
        if pending_request := self._pending_requests.pop(body.answer_msg_id, None):
            pending_request.finalize()

    def _process_msg_detailed_info(self, body: Structure) -> None:
        self._process_msg_new_detailed_info(body)
        self._msgids_to_ack.append(body.msg_id)

    def _process_future_salts(self, body: Structure) -> None:
        if pending_request := self._pending_requests.pop(body.req_msg_id, None):
            pending_request.response.set_result(body)
            pending_request.finalize()

        if pending_future_salt := self._pending_future_salt:
            pending_future_salt.cancel()

        self._datacenter.set_synchronized_time(body.now)

        if valid_salt := next((salt for salt in body.salts if salt.valid_since <= body.now), None):
            self._used_session_key.server_salt = valid_salt.salt

            salt_expire = max((valid_salt.valid_until - body.now) - 1800, 10)

            def _initialize_create_future_salt_request() -> None:
                if pending_future_salt := self._pending_future_salt:
                    pending_future_salt.cancel()

                self._pending_future_salt = self._loop.create_task(self._create_future_salt_request())

            self._pending_future_salt = self._loop.call_later(salt_expire, _initialize_create_future_salt_request)

            logging.debug("scheduling get_future_salts, current salt is valid for %i seconds", salt_expire)

        self._used_session_key.flush_changes()

    async def _process_new_session_created(self, body: Structure) -> None:
        self._used_session_key.server_salt = body.server_salt

    async def _process_updates(self, body: Structure) -> None:
        if self._no_updates:
            return

        users = body.users
        chats = body.chats

        for update in body.updates:
            await self._updates_queue.put(Update(users, chats, update))

    def _process_pong(self, pong: Structure) -> None:
        logging.debug("pong message: %d", pong.ping_id)

        if pending_pong := self._pending_pong:
            pending_pong.cancel()
            self._pending_pong = None

        if pending_request := self._pending_requests.pop(pong.msg_id, None):
            pending_request.response.set_result(pong)
            pending_request.finalize()

        if pending_ping := self._pending_ping:
            pending_ping.cancel()

        def _initialize_create_ping_request() -> None:
            if pending_ping := self._pending_ping:
                pending_ping.cancel()

            self._pending_ping = self._loop.create_task(self._create_ping_request())

        self._pending_ping = self._loop.call_later(30, _initialize_create_ping_request)

    def _acknowledge_telegram_message(self, signaling: Structure) -> None:
        if signaling.seqno % 2 == 1:
            self._msgids_to_ack.append(signaling.msg_id)

    async def _flush_msgids_to_ack(self) -> None:
        if not self._msgids_to_ack or not self._used_session_key.session.stable_seqno:
            return

        message: TlBodyData = dict(_cons="msgs_ack", msg_ids=self._msgids_to_ack.copy())
        self._msgids_to_ack.clear()

        request = PendingRequest(
            response=self._loop.create_future(),
            message=message,
            seq_no_func=self._used_session_key.get_next_even_seqno,
            allow_container=False,
            expect_answer=False
        )

        await self._rpc_call(request)

    def _process_telegram_signaling_message(self, signaling: Structure) -> None:
        self._used_session_key.session.seqno = max(self._used_session_key.session.seqno, signaling.seqno)
        self._acknowledge_telegram_message(signaling)

    async def _process_bad_server_salt(self, body: Structure) -> None:
        if self._used_session_key.server_salt:
            self._used_session_key.session.stable_seqno = False

        self._used_session_key.server_salt = body.new_server_salt
        logging.debug("updating salt: %d", body.new_server_salt)

        if bad_request := self._pending_requests.pop(body.bad_msg_id, None):
            await self._rpc_call(bad_request)
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

        self._used_session_key.flush_changes()

    async def _process_bad_msg_notification(self, body: Structure) -> None:
        if body.error_code == 32:
            await self._process_bad_msg_notification_msg_seqno_too_low(body)
        elif body.error_code == 33:
            await self._process_bad_msg_notification_msg_seqno_too_high(body)
        else:
            await self._process_bad_msg_notification_reject_message(body)

    async def _process_bad_msg_notification_reject_message(self, body: Structure) -> None:
        if bad_request := self._pending_requests.pop(body.bad_msg_id, None):
            bad_request.response.set_exception(RpcError(body.error_code, "BAD_MSG_NOTIFICATION", None))
            bad_request.finalize()
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

    async def _process_bad_msg_notification_msg_seqno_too_high(self, body: Structure) -> None:
        if bad_request := self._pending_requests.pop(body.bad_msg_id, None):
            await self._rpc_call(bad_request)
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

    async def _process_bad_msg_notification_msg_seqno_too_low(self, body: Structure) -> None:
        session = self._used_session_key.session

        session.seqno_increment = min(2 ** 31 - 1, session.seqno_increment << 1)
        session.seqno += session.seqno_increment

        logging.debug("updating seqno by %d to %d", session.seqno_increment, session.seqno)

        if bad_request := self._pending_requests.pop(body.bad_msg_id, None):
            await self._rpc_call(bad_request)
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

    async def _process_rpc_result(self, body: Structure) -> None:
        self._used_session_key.session.stable_seqno = True
        self._used_session_key.session.seqno_increment = 1

        pending_request = self._pending_requests.pop(body.req_msg_id, None)

        if pending_request is None:
            return logging.error("rpc_result %d not associated with a request", body.req_msg_id)

        if body.result.startswith(self._rpc_error_constructor.number):
            response_constructor = self._rpc_error_constructor
        else:
            response_constructor = None

        if request_type := pending_request.request.get("_cons", None):
            response_parameter = self._datacenter.schema.constructors[typing.cast(str, request_type)].ptype_parameter
        else:
            response_parameter = None

        body_result_reader = to_reader(body.result)

        try:
            if response_constructor is not None:
                result = Structure.from_obj(await self._in_thread(response_constructor.deserialize_boxed_data, body_result_reader))

            elif response_parameter is not None:
                result = Structure.from_obj(await self._in_thread(self._datacenter.schema.read_by_parameter, body_result_reader, response_parameter))

            else:
                result = Structure.from_obj(await self._in_thread(self._datacenter.schema.read_by_boxed_data, body_result_reader))
        finally:
            reader_discard(body_result_reader)

        if self._use_perfect_forward_secrecy and \
                result == "rpc_error" and \
                result.error_message == "AUTH_KEY_PERM_EMPTY":
            logging.error("auth key %r: not bound to permanent", self._used_session_key.auth_key_id)

            if not self._used_session_key.is_fresh_key():
                self._used_session_key.clear_key()
                self._used_session_key.flush_changes()

            return self.disconnect()

        if result == "rpc_error" and result.error_message == "CONNECTION_NOT_INITED" and pending_request.retries < 5:
            self._layer_init_required = True
            await self._rpc_call(pending_request)

        elif result == "rpc_error" and result.error_code >= 500 and pending_request.retries < 5:
            logging.debug("rpc_error with 5xx status `%r` for request %d", result, body.req_msg_id)
            await self._rpc_call(pending_request)

        elif result == "rpc_error":
            error_description_resolver = self._error_description_resolver
            error_description: str | None = None

            if error_description_resolver is not None:
                error_description = error_description_resolver.resolve(result.error_code, result.error_message)

            pending_request.response.set_exception(RpcError(result.error_code, result.error_message, error_description))
            pending_request.finalize()

        else:
            pending_request.response.set_result(result)

            if pending_request.allow_container:
                self._layer_init_required = False

            pending_request.finalize()

    def disconnect(self) -> None:
        self._layer_init_required = True

        if not self._no_updates:
            self._updates_queue.put_nowait(None)

        if pending_pong := self._pending_pong:
            pending_pong.cancel()

        self._pending_pong = None

        for pending_request in self._pending_requests.values():
            pending_request.finalize()

        self._pending_requests.clear()

        if pending_future_salt := self._pending_future_salt:
            pending_future_salt.cancel()

        self._pending_future_salt = None

        if pending_ping := self._pending_ping:
            pending_ping.cancel()

        self._pending_ping = None

        if mtproto_link := self._mtproto:
            mtproto_link.stop()

        if mtproto_loop := self._mtproto_loop_task:
            mtproto_loop.cancel()

        while not self._write_queue.empty():
            self._write_queue.get_nowait().finalize()

        self._mtproto_loop_task = None

    def __del__(self) -> None:
        if self._mtproto_loop_task is not None:
            logging.critical("client %d not disconnected", id(self))
