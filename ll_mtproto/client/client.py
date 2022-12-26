import asyncio
import concurrent.futures
import logging
import traceback
import typing
import warnings

from . import ConnectionInfo
from . import PendingRequest, Update
from ..crypto import AuthKey
from ..network import mtproto, DatacenterInfo
from ..network.mtproto import MTProto
from ..network.mtproto_key_exchange import MTProtoKeyExchange
from ..network.transport import TransportLinkFactory
from ..typed import TlMessageBody, Structure, RpcError, TlRequestBody

__all__ = ("Client",)


class Client:
    __slots__ = (
        "_mtproto",
        "_loop",
        "_msgids_to_ack",
        "_seqno_increment",
        "_mtproto_loop_task",
        "_pending_requests",
        "_pending_pong",
        "_datacenter",
        "_perm_auth_key",
        "_pending_ping",
        "_stable_seqno",
        "_updates_queue",
        "_no_updates",
        "_pending_future_salt",
        "_layer_init_info",
        "_layer_init_required",
        "_auth_key_lock",
        "_mtproto_key_exchange",
        "_use_perfect_forward_secrecy",
        "_temp_auth_key",
        "_blocking_executor",
        "_bound_auth_key",
        "_write_queue"
    )

    _mtproto: mtproto.MTProto
    _loop: asyncio.AbstractEventLoop
    _msgids_to_ack: list[int]
    _stable_seqno: bool
    _seqno_increment: int
    _mtproto_loop_task: asyncio.Task | None
    _pending_requests: dict[int, PendingRequest]
    _pending_pong: asyncio.TimerHandle | None
    _datacenter: DatacenterInfo
    _perm_auth_key: AuthKey
    _pending_ping: asyncio.TimerHandle | None
    _updates_queue: asyncio.Queue[Update | None]
    _no_updates: bool
    _pending_future_salt: asyncio.TimerHandle | None
    _layer_init_info: ConnectionInfo
    _layer_init_required: bool
    _auth_key_lock: asyncio.Lock
    _mtproto_key_exchange: MTProtoKeyExchange
    _use_perfect_forward_secrecy: bool
    _temp_auth_key: AuthKey | None
    _blocking_executor: concurrent.futures.Executor
    _bound_auth_key: AuthKey
    _write_queue: asyncio.Queue[PendingRequest]

    def __init__(
            self,
            datacenter: DatacenterInfo,
            auth_key: AuthKey,
            connection_info: ConnectionInfo,
            transport_link_factory: TransportLinkFactory,
            blocking_executor: concurrent.futures.Executor,
            no_updates: bool = True,
            use_perfect_forward_secrecy: bool = False,
    ):
        self._datacenter = datacenter
        self._perm_auth_key = auth_key
        self._layer_init_info = connection_info
        self._no_updates = no_updates
        self._use_perfect_forward_secrecy = use_perfect_forward_secrecy
        self._blocking_executor = blocking_executor

        self._loop = asyncio.get_running_loop()

        self._msgids_to_ack = []

        self._stable_seqno = False
        self._seqno_increment = 1

        self._layer_init_required = True

        self._pending_requests = dict()

        self._pending_pong = None
        self._pending_ping = None

        self._mtproto_loop_task = None
        self._pending_future_salt = None

        self._updates_queue = asyncio.Queue()
        self._write_queue = asyncio.Queue()

        self._auth_key_lock = asyncio.Lock()

        self._mtproto = MTProto(datacenter, transport_link_factory, self._in_thread)
        self._mtproto_key_exchange = MTProtoKeyExchange(self._mtproto, self._in_thread, datacenter)
        self._temp_auth_key = AuthKey() if self._use_perfect_forward_secrecy else None
        self._bound_auth_key = typing.cast(AuthKey, self._temp_auth_key) if self._use_perfect_forward_secrecy else self._perm_auth_key

        if use_perfect_forward_secrecy:
            warnings.warn("The use_perfect_forward_secrecy is currently a unstable API don't use it in production", FutureWarning)

    async def _in_thread(self, *args, **kwargs):
        return await self._loop.run_in_executor(self._blocking_executor, *args, **kwargs)

    async def get_update(self) -> Update | None:
        if self._no_updates:
            raise RuntimeError("the updates queue is always empty if no_updates has been set to true.")

        await self._start_mtproto_loop_if_needed()
        return await self._updates_queue.get()

    async def rpc_call(self, payload: TlRequestBody) -> TlMessageBody:
        pending_request = PendingRequest(self._loop.create_future(), payload, self._get_next_odd_seqno, True)
        pending_request.cleaner = self._loop.call_later(120, lambda: pending_request.finalize())
        await self._start_mtproto_loop_if_needed()
        await self._rpc_call(pending_request)
        return await pending_request.response

    async def _rpc_call(self, request: PendingRequest):
        self._ensure_mtproto_loop()
        await self._write_queue.put(request)

    def _wrap_request_in_layer_init(self, message: TlRequestBody) -> TlRequestBody:
        message = dict(_cons="initConnection", _wrapped=message, **self._layer_init_info.dict())
        message = dict(_cons="invokeWithLayer", _wrapped=message, layer=self._datacenter.schema.layer)

        if self._no_updates:
            message = dict(_cons="invokeWithoutUpdates", _wrapped=message)

        return message

    async def _start_mtproto_loop(self):
        self.disconnect()

        logging.debug("connecting to Telegram at %s", self._datacenter)
        self._mtproto_loop_task = self._loop.create_task(self._mtproto_loop())

        await self._create_init_requests()

    async def _create_init_requests(self):
        await self._create_ping_request()
        await self._create_future_salt_request()

    async def _create_future_salt_request(self):
        get_future_salts_message = dict(_cons="get_future_salts", num=2)
        get_future_salts_request = PendingRequest(self._loop.create_future(), get_future_salts_message, self._get_next_odd_seqno, False)

        if pending_future_salt := self._pending_future_salt:
            pending_future_salt.cancel()

        self._pending_future_salt = self._loop.call_later(
            30,
            lambda: self._loop.create_task(self._create_future_salt_request()))

        await self._rpc_call(get_future_salts_request)

    async def _create_ping_request(self):
        ping_id = self._mtproto.get_next_message_id()

        if pending_pong := self._pending_pong:
            pending_pong.cancel()

        self._pending_pong = self._loop.call_later(10, self.disconnect)

        ping_message = dict(_cons="ping", ping_id=ping_id)
        ping_request = PendingRequest(self._loop.create_future(), ping_message, self._get_next_odd_seqno, False)

        await self._rpc_call(ping_request)

    def _get_next_odd_seqno(self) -> int:
        self._bound_auth_key.seq_no = ((self._bound_auth_key.seq_no + 1) // 2) * 2 + 1
        return self._bound_auth_key.seq_no

    def _get_next_even_seqno(self) -> int:
        self._bound_auth_key.seq_no = (self._bound_auth_key.seq_no // 2 + 1) * 2
        return self._bound_auth_key.seq_no

    def _cancel_pending_request(self, msg_id: int):
        if pending_request := self._pending_requests.pop(msg_id, None):
            pending_request.finalize()

    async def _get_auth_key(self) -> AuthKey:
        self._ensure_mtproto_loop()

        async with self._auth_key_lock:
            perm_auth_key = self._perm_auth_key

            if perm_auth_key.is_empty():
                new_auth_key = await self._mtproto_key_exchange.create_perm_auth_key()
                new_auth_key.copy_to(perm_auth_key)

            if self._use_perfect_forward_secrecy:
                temp_auth_key = self._temp_auth_key

                if temp_auth_key.is_empty():
                    new_temp_auth_key = await self._mtproto_key_exchange.create_temp_auth_key(perm_auth_key)
                    new_temp_auth_key.copy_to(temp_auth_key)

                return temp_auth_key

            return perm_auth_key

    async def _process_inbound_message(self, message: TlMessageBody):
        logging.debug("received message (%s) %d from mtproto", message.body.constructor_name, message.msg_id)
        await self._process_telegram_message(message)
        await self._flush_msgids_to_ack()

    async def _process_outbound_message(self, message: PendingRequest):
        message.retries += 1

        if message.response.done():
            raise asyncio.InvalidStateError("request %r already completed", message.request)

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
            boxed_message, boxed_message_id = self._mtproto.prepare_message_for_write(seq_no=message.next_seq_no(), **request_body)
        except Exception as serialization_exception:
            message.response.set_exception(serialization_exception)
            message.finalize()
            return

        if message.expect_answer:
            self._pending_requests[boxed_message_id] = message

        message.cleaner = self._loop.call_later(120, self._cancel_pending_request, boxed_message_id)

        logging.debug("writing message %d (%s)", boxed_message_id, message.request["_cons"])

        await self._mtproto.write_encrypted(boxed_message, self._bound_auth_key)

    async def _mtproto_write_loop(self):
        while True:
            message = await self._write_queue.get()
            await self._process_outbound_message(message)

    async def _mtproto_read_loop(self):
        while True:
            await self._process_inbound_message(await self._mtproto.read_encrypted(self._bound_auth_key))

    async def _mtproto_loop(self):
        try:
            await self._get_auth_key()
        except:
            logging.debug("unable to generate mtproto auth key: %s", traceback.format_exc())
            self.disconnect()
            raise asyncio.CancelledError()

        write_task = self._loop.create_task(self._mtproto_write_loop())
        read_task = self._loop.create_task(self._mtproto_read_loop())

        try:
            await asyncio.gather(write_task, read_task)
        except (KeyboardInterrupt, asyncio.CancelledError, GeneratorExit):
            raise
        except:
            logging.error("unable to process message in consumer: %s", traceback.format_exc())
        finally:
            write_task.cancel()
            read_task.cancel()

        self.disconnect()
        raise asyncio.CancelledError()

    def _ensure_mtproto_loop(self):
        if mtproto_loop_task := self._mtproto_loop_task:
            if mtproto_loop_task.done():
                raise asyncio.InvalidStateError("mtproto loop closed")
        else:
            raise asyncio.InvalidStateError("mtproto loop closed")

    async def _start_mtproto_loop_if_needed(self):
        if mtproto_loop_task := self._mtproto_loop_task:
            if mtproto_loop_task.done():
                await self._start_mtproto_loop()
        else:
            await self._start_mtproto_loop()

    async def _process_telegram_message(self, message: Structure):
        self._update_last_seqno_from_incoming_message(message)

        body = message.body.packed_data if message.body == "gzip_packed" else message.body

        if body == "msg_container":
            for m in body.messages:
                await self._process_telegram_message(m)

        else:
            await self._process_telegram_message_body(body)
            await self._acknowledge_telegram_message(message)

    async def _process_telegram_message_body(self, body: TlMessageBody):
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

            case _:
                logging.critical("unknown message type (%s) received", constructor_name)

    async def _process_update_short_message(self, body: TlMessageBody):
        if not self._no_updates:
            await self._updates_queue.put(Update([], [], body))

    async def _process_update_short(self, body: TlMessageBody):
        if not self._no_updates:
            await self._updates_queue.put(Update([], [], body.update))

    def _process_msgs_ack(self, body: TlMessageBody):
        logging.debug("received msgs_ack %r", body.msg_ids)

    def _process_msgs_state_info(self, body: TlMessageBody):
        if pending_request := self._pending_requests.pop(body.req_msg_id, None):
            pending_request.response.set_result(body)
            pending_request.finalize()

    def _process_msg_new_detailed_info(self, body: TlMessageBody):
        if pending_request := self._pending_requests.pop(body.answer_msg_id, None):
            pending_request.finalize()

    def _process_msg_detailed_info(self, body: TlMessageBody):
        self._process_msg_new_detailed_info(body)
        self._msgids_to_ack.append(body.msg_id)

    def _process_future_salts(self, body: TlMessageBody):
        if pending_request := self._pending_requests.pop(body.req_msg_id, None):
            pending_request.response.set_result(body)
            pending_request.finalize()

        if pending_future_salt := self._pending_future_salt:
            pending_future_salt.cancel()

        self._datacenter.set_synchronized_time(body.now)

        if valid_salt := next((salt for salt in body.salts if salt.valid_since <= body.now), None):
            self._bound_auth_key.server_salt = valid_salt.salt

            salt_expire = max((valid_salt.valid_until - body.now) - 1800, 10)

            self._pending_future_salt = self._loop.call_later(
                salt_expire,
                lambda: self._loop.create_task(self._create_future_salt_request()))

            logging.debug("scheduling get_future_salts, current salt is valid for %i seconds", salt_expire)

    async def _process_new_session_created(self, body: TlMessageBody):
        self._bound_auth_key.server_salt = body.server_salt

    async def _process_updates(self, body: TlMessageBody):
        if self._no_updates:
            return

        users = body.users
        chats = body.chats

        for update in body.updates:
            await self._updates_queue.put(Update(users, chats, update))

    def _process_pong(self, pong: TlMessageBody):
        logging.debug("pong message: %d", pong.ping_id)

        if pending_pong := self._pending_pong:
            pending_pong.cancel()
            self._pending_pong = None

        if pending_request := self._pending_requests.pop(pong.msg_id, None):
            pending_request.response.set_result(pong)
            pending_request.finalize()

        if pending_ping_request := self._pending_ping:
            pending_ping_request.cancel()

        self._pending_ping = self._loop.call_later(30, lambda: self._loop.create_task(self._create_ping_request()))

    async def _acknowledge_telegram_message(self, message: Structure):
        if message.seqno % 2 == 1:
            self._msgids_to_ack.append(message.msg_id)

    async def _flush_msgids_to_ack(self):
        if not self._msgids_to_ack or not self._stable_seqno:
            return

        msgids_to_ack_message = dict(_cons="msgs_ack", msg_ids=self._msgids_to_ack.copy())
        msgids_to_ack_request = PendingRequest(self._loop.create_future(), msgids_to_ack_message, self._get_next_even_seqno, False, expect_answer=False)
        self._msgids_to_ack.clear()

        await self._rpc_call(msgids_to_ack_request)

    def _update_last_seqno_from_incoming_message(self, message: Structure):
        self._bound_auth_key.seq_no = max(self._bound_auth_key.seq_no, message.seqno)

    async def _process_bad_server_salt(self, body: TlMessageBody):
        if self._bound_auth_key.server_salt:
            self._stable_seqno = False

        self._bound_auth_key.server_salt = body.new_server_salt
        logging.debug("updating salt: %d", body.new_server_salt)

        if bad_request := self._pending_requests.pop(body.bad_msg_id, None):
            await self._rpc_call(bad_request)
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

    async def _process_bad_msg_notification(self, body: TlMessageBody):
        if body.error_code == 32:
            await self._process_bad_msg_notification_msg_seqno_too_low(body)
        elif body.error_code == 33:
            await self._process_bad_msg_notification_msg_seqno_too_high(body)
        else:
            await self._process_bad_msg_notification_reject_message(body)

    async def _process_bad_msg_notification_reject_message(self, body: TlMessageBody):
        if bad_request := self._pending_requests.pop(body.bad_msg_id, None):
            bad_request.response.set_exception(RpcError(body.error_code, "BAD_MSG_NOTIFICATION"))
            bad_request.finalize()
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

    async def _process_bad_msg_notification_msg_seqno_too_high(self, body: TlRequestBody):
        if bad_request := self._pending_requests.pop(body.bad_msg_id, None):
            await self._rpc_call(bad_request)
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

    async def _process_bad_msg_notification_msg_seqno_too_low(self, body: TlMessageBody):
        self._seqno_increment = min(2 ** 31 - 1, self._seqno_increment << 1)
        self._bound_auth_key.seq_no += self._seqno_increment

        logging.debug("updating seqno by %d to %d", self._seqno_increment, self._bound_auth_key.seq_no)

        if bad_request := self._pending_requests.pop(body.bad_msg_id, None):
            await self._rpc_call(bad_request)
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

    async def _process_rpc_result(self, body: TlMessageBody):
        self._stable_seqno = True
        self._seqno_increment = 1

        if pending_request := self._pending_requests.pop(body.req_msg_id, None):
            if body.result == "gzip_packed":
                result = body.result.packed_data
            else:
                result = body.result

            if pending_request.allow_container:
                self._layer_init_required = False

            if result == "rpc_error" and result.error_code >= 500 and pending_request.retries < 5:
                logging.debug("rpc_error with 5xx status `%r` for request %d", result, body.req_msg_id)
                await self._rpc_call(pending_request)

            elif result == "rpc_error":
                pending_request.response.set_exception(RpcError(result.error_code, result.error_message))
                pending_request.finalize()

            else:
                pending_request.response.set_result(result)
                pending_request.finalize()

    def disconnect(self):
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

        if pending_ping_request := self._pending_ping:
            pending_ping_request.cancel()

        self._pending_ping = None

        if mtproto_link := self._mtproto:
            mtproto_link.stop()

        if mtproto_loop := self._mtproto_loop_task:
            mtproto_loop.cancel()

        while not self._write_queue.empty():
            message = self._write_queue.get_nowait()

            if isinstance(message, list):
                for submessage in message:
                    submessage.finalize()
            else:
                message.finalize()

        self._mtproto_loop_task = None

    def __del__(self):
        if self._mtproto_loop_task is not None:
            logging.critical("client %d not disconnected", id(self))
