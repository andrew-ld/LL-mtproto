# Copyright (C) 2017-2018 (nikat) https://github.com/nikat/mtproto2json
# Copyright (C) 2020-2025 (andrew) https://github.com/andrew-ld/LL-mtproto
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
from ll_mtproto.client.pending_container_request import PendingContainerRequest
from ll_mtproto.client.pending_request import PendingRequest
from ll_mtproto.client.rpc_error import RpcErrorException
from ll_mtproto.crypto.auth_key import AuthKey, Key, AuthKeyUpdatedCallback
from ll_mtproto.crypto.providers.crypto_provider_base import CryptoProviderBase
from ll_mtproto.in_thread import InThread
from ll_mtproto.network.auth_key_not_found_exception import AuthKeyNotFoundException
from ll_mtproto.network.datacenter_info import DatacenterInfo
from ll_mtproto.network.dh.mtproto_key_binder_dispatcher import MTProtoKeyBinderDispatcher
from ll_mtproto.network.dh.mtproto_key_creator_dispatcher import initialize_key_creator_dispatcher
from ll_mtproto.network.dispatcher import Dispatcher, dispatch_event, SignalingMessage
from ll_mtproto.network.mtproto import MTProto
from ll_mtproto.network.transport.transport_link_factory import TransportLinkFactory
from ll_mtproto.tl.structure import BaseStructure, StructureValue, TypedStructure, TypedStructureObjectType, DynamicStructure
from ll_mtproto.tl.tl import TlBodyData, NativeByteReader, Value, extract_cons_from_tl_body, extract_cons_from_tl_body_opt, TlBodyDataValue
from ll_mtproto.tl.tl_utils import TypedSchemaConstructor, flat_value_buffer
from ll_mtproto.tl.tls_system import RpcError, DestroySessionOk, DestroySessionNone, FutureSalts, RpcResult, BadServerSalt, BadMsgNotification, \
    NewSessionCreated, Pong, MessageFromServer, MessageFromClient, UnencryptedMessage, MsgsAck

__all__ = ("Client", "ClientInThread")


# noinspection PyProtectedMember
class _ClientDispatcher(Dispatcher):
    __slots__ = ("_impl",)

    _impl: "Client"

    def __init__(self, impl: "Client"):
        self._impl = impl

    async def process_telegram_message_body(self, body: BaseStructure, crypto_flag: bool) -> None:
        if not crypto_flag:
            raise RuntimeError("process_telegram_message_body accepts only encrypted messages")
        await self._impl._process_telegram_message_body(body)

    async def process_telegram_signaling_message(self, signaling: SignalingMessage, crypto_flag: bool) -> None:
        if not crypto_flag:
            raise RuntimeError("process_telegram_signaling_message accepts only encrypted messages")
        self._impl._process_telegram_signaling_message(signaling)


class ClientInThread(InThread):
    __slots__ = ("_blocking_executor",)

    def __init__(self, blocking_executor: concurrent.futures.Executor):
        self._blocking_executor = blocking_executor

    def __call__(self, target: typing.Callable[[], InThread.InThreadRetType]) -> asyncio.Future[InThread.InThreadRetType]:
        return asyncio.get_running_loop().run_in_executor(self._blocking_executor, target)


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
        "_connection_info",
        "_init_connection_required",
        "_auth_key_lock",
        "_use_perfect_forward_secrecy",
        "_write_queue",
        "_used_session_key",
        "_used_persistent_key",
        "_rpc_error_constructor",
        "_dispatcher",
        "_crypto_provider",
        "_error_description_resolver",
        "_in_thread",
        "_transport_link_factory",
        "_blocking_executor",
        "_default_timeout_seconds",
        "_on_server_side_error_retries"
    )

    _mtproto: MTProto | None
    _loop: asyncio.AbstractEventLoop
    _msgids_to_ack: list[int]
    _mtproto_loop_task: asyncio.Task[None] | None
    _pending_requests: dict[int, PendingRequest | PendingContainerRequest]
    _pending_pong: asyncio.TimerHandle | None
    _datacenter: DatacenterInfo
    _pending_ping: asyncio.TimerHandle | asyncio.Task[None] | None
    _updates_queue: asyncio.Queue[BaseStructure | None]
    _no_updates: bool
    _pending_future_salt: asyncio.TimerHandle | asyncio.Task[None] | None
    _connection_info: ConnectionInfo
    _init_connection_required: bool
    _auth_key_lock: asyncio.Lock
    _use_perfect_forward_secrecy: bool
    _blocking_executor: concurrent.futures.Executor
    _write_queue: asyncio.Queue[PendingRequest | PendingContainerRequest]
    _used_session_key: Key
    _used_persistent_key: Key
    _rpc_error_constructor: TypedSchemaConstructor[RpcError]
    _dispatcher: _ClientDispatcher
    _crypto_provider: CryptoProviderBase
    _error_description_resolver: BaseErrorDescriptionResolver | None
    _in_thread: InThread
    _transport_link_factory: TransportLinkFactory
    _default_timeout_seconds: int
    _on_server_side_error_retries: int

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
            error_description_resolver: BaseErrorDescriptionResolver | None = None,
            default_timeout_seconds: int = 120,
            on_server_side_error_retries: int = 5,
    ):
        self._datacenter = datacenter
        self._connection_info = connection_info
        self._no_updates = no_updates
        self._use_perfect_forward_secrecy = use_perfect_forward_secrecy
        self._crypto_provider = crypto_provider
        self._error_description_resolver = error_description_resolver
        self._transport_link_factory = transport_link_factory
        self._blocking_executor = blocking_executor
        self._default_timeout_seconds = default_timeout_seconds
        self._on_server_side_error_retries = on_server_side_error_retries

        self._in_thread = ClientInThread(blocking_executor)
        self._rpc_error_constructor = TypedSchemaConstructor(datacenter.schema, RpcError)

        self._loop = asyncio.get_running_loop()
        self._auth_key_lock = asyncio.Lock()

        self._msgids_to_ack = list()
        self._pending_requests = dict()
        self._init_connection_required = True

        self._pending_pong = None
        self._pending_ping = None
        self._pending_future_salt = None

        self._mtproto_loop_task = None
        self._updates_queue = asyncio.Queue()
        self._write_queue = asyncio.Queue()
        self._dispatcher = _ClientDispatcher(self)

        self._mtproto = None

        self._used_session_key = auth_key.temporary_key if use_perfect_forward_secrecy else auth_key.persistent_key
        self._used_persistent_key = auth_key.persistent_key

    def to_media_datacenter(
            self,
            media_datacenter_info: DatacenterInfo,
            auth_key_callback: AuthKeyUpdatedCallback | None = None,
            force_pfs: bool | None = None
    ) -> "Client":
        if media_datacenter_info.datacenter_id != self._datacenter.datacenter_id:
            raise TypeError(f"The specified datacenter info id mismatches the main datacenter id `{media_datacenter_info!r}`")

        if force_pfs is None:
            use_pfs = self._use_perfect_forward_secrecy
        else:
            use_pfs = force_pfs

        auth_key = AuthKey()
        auth_key.persistent_key.auth_key = self._used_persistent_key.auth_key
        auth_key.persistent_key.auth_key_id = self._used_persistent_key.auth_key_id
        auth_key.persistent_key.server_salt = self._used_persistent_key.server_salt

        if auth_key_callback is not None:
            auth_key.set_content_change_callback(auth_key_callback)

        client = Client(
            datacenter=media_datacenter_info,
            auth_key=auth_key,
            connection_info=self._connection_info,
            use_perfect_forward_secrecy=use_pfs,
            blocking_executor=self._blocking_executor,
            error_description_resolver=self._error_description_resolver,
            crypto_provider=self._crypto_provider,
            no_updates=True,
            transport_link_factory=self._transport_link_factory
        )

        return client

    async def get_update(self) -> BaseStructure | None:
        if self._no_updates:
            raise RuntimeError("the updates queue is always empty if no_updates has been set to true.")

        await self._start_mtproto_loop_if_needed()
        return await self._updates_queue.get()

    async def rpc_call_container(
            self,
            payloads: list[TlBodyData | BaseStructure] | list[TypedStructure[typing.Any]],
            force_init_connection: bool = False,
            serialized_payloads: list[Value] | None = None,
            timeout_seconds: int | None = None
    ) -> list[StructureValue | BaseException]:
        if not payloads:
            return []

        if timeout_seconds is None:
            timeout_seconds = self._default_timeout_seconds

        payloads_as_body_data: list[TlBodyData] = list(
            p.as_tl_body_data() if isinstance(p, BaseStructure) else p
            for p in payloads
        )

        if serialized_payloads is None:
            serialized_payloads = await self._in_thread(lambda: list(map(self._datacenter.schema.boxed, payloads_as_body_data)))

        if len(serialized_payloads) != len(payloads_as_body_data):
            raise TypeError("serialized payloads len and payloads len mismatches")

        for payload, serialized_payload in zip(payloads_as_body_data, serialized_payloads):
            payload_cons = extract_cons_from_tl_body(payload)
            serialized_payload_cons = serialized_payload.cons.name

            if payload_cons != serialized_payload_cons:
                raise TypeError(f"Serialized payload constructor type `{serialized_payload_cons!r}` mismatches payload cons `{payload_cons!r}`")

        pending_requests: list[PendingRequest] = []

        for payload, serialized_payload in zip(payloads_as_body_data, serialized_payloads):
            pending_request = PendingRequest(
                response=self._loop.create_future(),
                message=payload,
                seq_no_func=self._used_session_key.get_next_odd_seqno,
                allow_container=True,
                expect_answer=True,
                force_init_connection=force_init_connection,
                serialized_payload=serialized_payload,
                timeout_seconds=timeout_seconds
            )

            pending_request.cleaner = self._loop.call_later(timeout_seconds, lambda: self._finalize_request_and_cleanup(pending_request))
            pending_requests.append(pending_request)

        await self._start_mtproto_loop_if_needed()
        await self._rpc_call(PendingContainerRequest(pending_requests))

        await asyncio.wait((request.response for request in pending_requests), return_when=asyncio.ALL_COMPLETED)

        return [request.get_value() for request in pending_requests]

    @typing.overload
    async def rpc_call(
            self,
            payload: TlBodyData,
            force_init_connection: bool = False,
            serialized_payload: Value | None = None,
            timeout_seconds: int | None = None,
    ) -> StructureValue:
        ...

    @typing.overload
    async def rpc_call(
            self,
            payload: TypedStructure[TypedStructureObjectType],
            force_init_connection: bool = False,
            serialized_payload: Value | None = None,
            timeout_seconds: int | None = None,
    ) -> TypedStructureObjectType:
        ...

    async def rpc_call(
            self,
            payload: TlBodyData | TypedStructure[TypedStructureObjectType] | BaseStructure,
            force_init_connection: bool = False,
            serialized_payload: Value | None = None,
            timeout_seconds: int | None = None,
    ) -> StructureValue | TypedStructureObjectType:
        if isinstance(payload, BaseStructure):
            payload = payload.as_tl_body_data()

        if timeout_seconds is None:
            timeout_seconds = self._default_timeout_seconds

        if serialized_payload is None:
            serialized_payload = await self._in_thread(lambda: self._datacenter.schema.boxed(payload))

        payload_cons = extract_cons_from_tl_body(payload)
        serialized_payload_cons = serialized_payload.cons.name

        if payload_cons != serialized_payload_cons:
            raise TypeError(f"Serialized payload constructor type `{serialized_payload_cons!r}` mismatches payload cons `{payload_cons!r}`")

        pending_request = PendingRequest(
            response=self._loop.create_future(),
            message=payload,
            seq_no_func=self._used_session_key.get_next_odd_seqno,
            allow_container=True,
            expect_answer=True,
            force_init_connection=force_init_connection,
            serialized_payload=serialized_payload,
            timeout_seconds=timeout_seconds
        )

        pending_request.cleaner = self._loop.call_later(timeout_seconds, lambda: self._finalize_request_and_cleanup(pending_request))

        await self._start_mtproto_loop_if_needed()
        await self._rpc_call(pending_request)

        return await pending_request.response

    async def _rpc_call(self, request: PendingRequest | PendingContainerRequest) -> None:
        self._ensure_mtproto_loop()
        await self._write_queue.put(request)

    def _wrap_into_init_connection(self, message: TlBodyData | Value) -> TlBodyData:
        layer = self._datacenter.schema.layer

        if layer is None:
            raise TypeError(f"schema layer number is None: `{self._datacenter.schema!s}`")

        message = dict(_cons="initConnection", _wrapped=message, **self._connection_info.to_request_body())
        message = dict(_cons="invokeWithLayer", _wrapped=message, layer=layer)

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

    def _pop_pending_request_exact(self, message_id: int) -> PendingRequest | None:
        pending_request = self._pending_requests.pop(message_id, None)

        if pending_request is None:
            return None

        if not isinstance(pending_request, PendingRequest):
            raise RuntimeError(f"message id `{message_id} is not a PendingRequest: `{pending_request!r}`")

        return pending_request

    async def _create_destroy_session_request(self, destroyed_session_id: int) -> None:
        destroy_session_message: TlBodyData = dict(_cons="destroy_session", session_id=destroyed_session_id)

        destroy_session_request = PendingRequest(
            response=self._loop.create_future(),
            message=destroy_session_message,
            seq_no_func=self._used_session_key.get_next_odd_seqno,
            allow_container=False,
            expect_answer=False,
            serialized_payload=None
        )

        await self._rpc_call(destroy_session_request)

    async def _create_future_salt_request(self) -> None:
        get_future_salts_message: TlBodyData = dict(_cons="get_future_salts", num=32)

        get_future_salts_request = PendingRequest(
            response=self._loop.create_future(),
            message=get_future_salts_message,
            seq_no_func=self._used_session_key.get_next_odd_seqno,
            allow_container=False,
            expect_answer=True,
            serialized_payload=None
        )

        if pending_future_salt := self._pending_future_salt:
            pending_future_salt.cancel()

        def _initialize_future_salt_request() -> None:
            if new_pending_future_salt := self._pending_future_salt:
                new_pending_future_salt.cancel()

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
            expect_answer=True,
            serialized_payload=None
        )

        await self._rpc_call(ping_request)

    def _cancel_pending_request(self, msg_id: int) -> None:
        if pending_request := self._pop_pending_request_exact(msg_id):
            self._finalize_request_and_cleanup(pending_request)

    def _cleanup_container_request_from_request(self, request: PendingRequest) -> None:
        container_message_id = request.container_message_id

        if container_message_id is None:
            return

        container_message = self._pending_requests.get(container_message_id, None)

        if container_message is None:
            return

        if not isinstance(container_message, PendingContainerRequest):
            raise TypeError(fr"Message id `{container_message_id!r}` is not PendingContainerRequest: `{container_message!r}`")

        if all(r.response.done() for r in container_message.requests):
            self._pending_requests.pop(container_message_id, None)

            if container_message_last_message_id := container_message.last_message_id:
                self._pending_requests.pop(container_message_last_message_id, None)

    def _finalize_request_and_cleanup(self, request: PendingRequest) -> None:
        if last_message_id := request.last_message_id:
            self._pending_requests.pop(last_message_id, None)

        request.finalize()

        self._cleanup_container_request_from_request(request)

    async def _start_auth_key_exchange_for_key(self, key: Key, is_temp_key: bool, mtproto: MTProto) -> None:
        dispatcher, result = await initialize_key_creator_dispatcher(
            is_temp_key,
            mtproto,
            self._in_thread,
            self._datacenter,
            self._crypto_provider
        )

        while not result.done():
            await dispatch_event(dispatcher, mtproto, None)

        key.import_dh_gen_key(result.result())

    async def _start_auth_key_bind_for_keys(self, persistent: Key, temp: Key, mtproto: MTProto) -> None:
        expire_at = temp.expire_at

        if expire_at is None:
            raise TypeError(f"Temp key expire_at is None: `{temp!r}`")

        dispatcher, result = await MTProtoKeyBinderDispatcher.initialize(
            persistent,
            temp,
            self._in_thread,
            self._datacenter,
            mtproto,
            self._crypto_provider,
            self._dispatcher,
            expire_at
        )

        while not result.done():
            await dispatch_event(dispatcher, mtproto, temp)

    async def _start_auth_key_exchange_if_needed(self, mtproto: MTProto) -> None:
        self._ensure_mtproto_loop()

        async with self._auth_key_lock:
            used_key = self._used_session_key
            persistent_key = self._used_persistent_key

            if persistent_key.is_empty():
                await self._start_auth_key_exchange_for_key(persistent_key, False, mtproto)
                persistent_key.flush_changes()

            if self._use_perfect_forward_secrecy:
                if used_key.expire_at is not None and self._datacenter.get_synchronized_time() >= used_key.expire_at:
                    used_key.clear_key()
                    used_key.flush_changes()

                if used_key.is_empty():
                    await self._start_auth_key_exchange_for_key(used_key, True, mtproto)
                    await self._start_auth_key_bind_for_keys(persistent_key, used_key, mtproto)
                    used_key.flush_changes()

            elif used_key is not persistent_key:
                raise RuntimeError(f"used key ({id(used_key)}) is not equal to persistent key {id(persistent_key)} and pfs is disabled")

    async def _prepare_outbound_message(self, message: PendingRequest, mtproto: MTProto) -> tuple[Value, int]:
        message.retries += 1

        if message.response.done():
            raise RuntimeError(f"Message `{message!r}` already completed")

        if last_message_id := message.last_message_id:
            self._pending_requests.pop(last_message_id, None)

        if cleaner := message.cleaner:
            cleaner.cancel()

        if message.force_init_connection:
            init_connection_required = True
        elif message.allow_container:
            init_connection_required = self._init_connection_required
        else:
            init_connection_required = False

        message.init_connection_wrapped = init_connection_required

        request_body: TlBodyData | Value | None = message.serialized_payload

        if request_body is None:
            request_body = message.serialized_payload = await self._in_thread(lambda: self._datacenter.schema.boxed(message.request))

        if init_connection_required:
            request_body = self._wrap_into_init_connection(request_body)

        payload, message_id = await self._in_thread(lambda: mtproto.prepare_message_for_write(message.next_seq_no(), request_body))

        message.last_message_id = message_id

        if message.expect_answer:
            self._pending_requests[message_id] = message

            timeout_seconds = message.timeout_seconds

            if timeout_seconds is None:
                timeout_seconds = self._default_timeout_seconds

            message.cleaner = self._loop.call_later(timeout_seconds, self._cancel_pending_request, message_id)

        return payload, message_id

    async def _process_outbound_message(self, message: PendingRequest, mtproto: MTProto) -> None:
        payload, message_id = await self._prepare_outbound_message(message, mtproto)
        message.container_message_id = None
        logging.debug("writing message %d (%s)", message_id, extract_cons_from_tl_body_opt(message.request))
        await mtproto.write_encrypted(payload, self._used_session_key)

    async def _process_outbound_container_message(self, message: PendingContainerRequest, mtproto: MTProto) -> None:
        if last_message_id := message.last_message_id:
            self._pending_requests.pop(last_message_id, None)

        pending_requests = [request for request in message.requests if not request.response.done()]

        if not pending_requests:
            return

        payloads: list[Value] = []

        for request in pending_requests:
            payload, _ = await self._prepare_outbound_message(request, mtproto)
            payloads.append(payload)

        container_body, container_message_id = mtproto.prepare_message_for_write(
            seq_no=self._used_session_key.get_next_even_seqno(),
            body=dict(
                _cons="msg_container",
                messages=payloads
            )
        )

        for request in pending_requests:
            request.container_message_id = container_message_id

        message.last_message_id = container_message_id

        self._pending_requests[container_message_id] = message

        logging.debug("writing container message %d", container_message_id)

        await mtproto.write_encrypted(container_body, self._used_session_key)

    async def _mtproto_write_loop(self, mtproto: MTProto) -> None:
        while True:
            request = await self._write_queue.get()

            match request:
                case PendingRequest():
                    await self._process_outbound_message(request, mtproto)

                case PendingContainerRequest():
                    await self._process_outbound_container_message(request, mtproto)

                case _:
                    raise TypeError(fr"Unexpected object in write queue `{request!r}`")

    async def _mtproto_read_loop(self, mtproto: MTProto) -> None:
        while True:
            await dispatch_event(self._dispatcher, mtproto, self._used_session_key)
            await self._flush_msgids_to_ack()

    async def _mtproto_loop(self) -> None:
        if mtproto := self._mtproto:
            mtproto.close()

        mtproto = self._mtproto = MTProto(self._datacenter, self._transport_link_factory, self._in_thread, self._crypto_provider)

        try:
            await self._start_auth_key_exchange_if_needed(mtproto)
        except (KeyboardInterrupt, asyncio.CancelledError, GeneratorExit):
            raise
        except:
            logging.debug("unable to generate mtproto auth key: %s", traceback.format_exc())
            self.disconnect()
            raise asyncio.CancelledError()

        self._used_session_key.generate_new_unique_session_id()
        self._used_session_key.flush_changes()

        read_task = self._loop.create_task(self._mtproto_read_loop(mtproto))
        write_task = self._loop.create_task(self._mtproto_write_loop(mtproto))

        for unused_session in self._used_session_key.unused_sessions:
            await self._create_destroy_session_request(unused_session)

        # noinspection PyBroadException
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

    async def _process_telegram_message_body(self, body: BaseStructure) -> None:
        match body:
            case RpcResult():
                await self._process_rpc_result(body)

            case BadServerSalt():
                await self._process_bad_server_salt(body)

            case BadMsgNotification():
                await self._process_bad_msg_notification(body)

            case NewSessionCreated():
                await self._process_new_session_created(body)

            case Pong():
                self._process_pong(body)

            case FutureSalts():
                self._process_future_salts(body)

            case MsgsAck():
                pass

            case DestroySessionOk() | DestroySessionNone():
                self._process_session_destroy(body)

            case "updates" | "updatesCombined" | "updateShort" | "updateShortMessage" | "updateShortChatMessage" | "updateShortSentMessage":
                await self._process_updates(body)

            case _:
                logging.critical("unknown message type (%s) received", body)

    def _process_session_destroy(self, body: DestroySessionOk | DestroySessionNone) -> None:
        logging.debug("session destroy received: %s", body.constructor_name)
        self._used_session_key.unused_sessions.remove(body.session_id)
        self._used_session_key.flush_changes()

    def _process_future_salts(self, body: FutureSalts) -> None:
        if pending_request := self._pop_pending_request_exact(body.req_msg_id):
            pending_request.response.set_result(body)
            self._finalize_request_and_cleanup(pending_request)

        if pending_future_salt := self._pending_future_salt:
            pending_future_salt.cancel()

        self._datacenter.set_synchronized_time(body.now)

        if (valid_salt := next((salt for salt in body.salts if salt.valid_since <= body.now), None)) is not None:
            self._used_session_key.server_salt = valid_salt.salt

            salt_expire = max((valid_salt.valid_until - body.now) - 1800, 10)

            def _initialize_create_future_salt_request() -> None:
                if new_pending_future_salt := self._pending_future_salt:
                    new_pending_future_salt.cancel()

                self._pending_future_salt = self._loop.create_task(self._create_future_salt_request())

            self._pending_future_salt = self._loop.call_later(salt_expire, _initialize_create_future_salt_request)

            logging.debug("scheduling get_future_salts, current salt is valid for %i seconds", salt_expire)

        self._used_session_key.flush_changes()

    async def _process_new_session_created(self, body: NewSessionCreated) -> None:
        self._used_session_key.server_salt = body.server_salt

    async def _process_updates(self, body: BaseStructure) -> None:
        if self._no_updates:
            return

        await self._updates_queue.put(body)

    def _process_pong(self, pong: Pong) -> None:
        logging.debug("pong message: %d", pong.ping_id)

        if pending_pong := self._pending_pong:
            pending_pong.cancel()
            self._pending_pong = None

        if pending_request := self._pop_pending_request_exact(pong.msg_id):
            pending_request.response.set_result(pong)
            self._finalize_request_and_cleanup(pending_request)

        if pending_ping := self._pending_ping:
            pending_ping.cancel()

        def _initialize_create_ping_request() -> None:
            if new_pending_ping := self._pending_ping:
                new_pending_ping.cancel()

            self._pending_ping = self._loop.create_task(self._create_ping_request())

        self._pending_ping = self._loop.call_later(30, _initialize_create_ping_request)

    def _acknowledge_telegram_message(self, signaling: MessageFromClient | MessageFromServer) -> None:
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
            expect_answer=False,
            serialized_payload=None
        )

        await self._rpc_call(request)

    def _process_telegram_signaling_message(self, signaling: SignalingMessage) -> None:
        if not isinstance(signaling, UnencryptedMessage):
            self._used_session_key.session.seqno = max(self._used_session_key.session.seqno, signaling.seqno)
            self._acknowledge_telegram_message(signaling)

    async def _process_bad_server_salt(self, body: BadServerSalt) -> None:
        if self._used_session_key.server_salt:
            self._used_session_key.session.stable_seqno = False

        self._used_session_key.server_salt = body.new_server_salt
        logging.debug("updating salt: %d", body.new_server_salt)

        if bad_request := self._pending_requests.pop(body.bad_msg_id, None):
            await self._rpc_call(bad_request)
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

        self._used_session_key.flush_changes()

    async def _process_bad_msg_notification(self, body: BadMsgNotification) -> None:
        if body.error_code == 32:
            await self._process_bad_msg_notification_msg_seqno_too_low(body)
        elif body.error_code == 33:
            await self._process_bad_msg_notification_msg_seqno_too_high(body)
        else:
            await self._process_bad_msg_notification_reject_message(body)

    async def _process_bad_msg_notification_reject_message(self, body: BadMsgNotification) -> None:
        if bad_request := self._pending_requests.pop(body.bad_msg_id, None):
            rpc_error = RpcErrorException(body.error_code, "BAD_MSG_NOTIFICATION", None)

            match bad_request:
                case PendingContainerRequest():
                    for request in bad_request.requests:
                        request.response.set_exception(rpc_error)
                        self._finalize_request_and_cleanup(request)

                case PendingRequest():
                    bad_request.response.set_exception(rpc_error)
                    self._finalize_request_and_cleanup(bad_request)

                case _:
                    raise TypeError(fr"Unexpected object in pending messages `{bad_request!r}`")
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

    async def _process_bad_msg_notification_msg_seqno_too_high(self, body: BadMsgNotification) -> None:
        if bad_request := self._pending_requests.pop(body.bad_msg_id, None):
            await self._rpc_call(bad_request)
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

    async def _process_bad_msg_notification_msg_seqno_too_low(self, body: BadMsgNotification) -> None:
        session = self._used_session_key.session

        session.seqno_increment = min(2 ** 31 - 1, session.seqno_increment << 1)
        session.seqno += session.seqno_increment

        logging.debug("updating seqno by %d to %d", session.seqno_increment, session.seqno)

        if bad_request := self._pending_requests.pop(body.bad_msg_id, None):
            await self._rpc_call(bad_request)
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

    def _finalize_response_throw_rpc_error(self, error_message: str, error_code: int, pending_request: PendingRequest) -> None:
        if (error_description_resolver := self._error_description_resolver) is not None:
            error_description = error_description_resolver.resolve(error_code, error_message)
        else:
            error_description = None

        pending_request.response.set_exception(RpcErrorException(error_code, error_message, error_description))
        self._finalize_request_and_cleanup(pending_request)

    async def _process_rpc_result(self, body: RpcResult) -> None:
        self._used_session_key.session.stable_seqno = True
        self._used_session_key.session.seqno_increment = 1

        pending_request = self._pop_pending_request_exact(body.req_msg_id)

        if pending_request is None:
            return logging.error("rpc_result %d not associated with a request", body.req_msg_id)

        if self._rpc_error_constructor.boxed_buffer_match(body.result):
            response_constructor = self._rpc_error_constructor.cons
        else:
            response_constructor = None

        if request_cons_cons := extract_cons_from_tl_body_opt(pending_request.request):
            request_body = pending_request.request
            request_cons = self._datacenter.schema.constructors[request_cons_cons]

            while request_cons.is_gzip_container:
                request_body = typing.cast(TlBodyData, request_body["data"])
                request_cons = self._datacenter.schema.constructors[extract_cons_from_tl_body(request_body)]

            response_parameter = request_cons.ptype_parameter
        else:
            response_parameter = None

        body_result_reader = NativeByteReader(flat_value_buffer(body.result))

        result_body: TlBodyDataValue

        try:
            if response_constructor is not None:
                result_body = await self._in_thread(lambda: response_constructor.deserialize_boxed_data(body_result_reader))

            elif response_parameter is not None:
                result_body = await self._in_thread(lambda: self._datacenter.schema.read_by_parameter(body_result_reader, response_parameter))

            else:
                result_body = await self._in_thread(lambda: self._datacenter.schema.read_by_boxed_data(body_result_reader))
        finally:
            del body_result_reader

        result = DynamicStructure.from_obj(result_body)
        del result_body

        if isinstance(result, RpcError):
            if result.error_message == "AUTH_KEY_PERM_EMPTY":
                if self._use_perfect_forward_secrecy:
                    self._used_session_key.clear_key()
                    self._used_session_key.flush_changes()
                    self.disconnect()

                else:
                    self._finalize_response_throw_rpc_error(result.error_message, result.error_code, pending_request)

            elif pending_request.retries >= self._on_server_side_error_retries:
                self._finalize_response_throw_rpc_error(result.error_message, result.error_code, pending_request)

            elif result.error_message == "CONNECTION_NOT_INITED":
                self._init_connection_required = True
                if pending_request.allow_container:
                    pending_request.force_init_connection = True
                await self._rpc_call(pending_request)

            elif 500 <= result.error_code < 600:
                logging.debug("rpc_error with 5xx status `%r` for request %d", result, body.req_msg_id)
                await self._rpc_call(pending_request)

            else:
                self._finalize_response_throw_rpc_error(result.error_message, result.error_code, pending_request)
        else:
            if pending_request.init_connection_wrapped:
                self._init_connection_required = False
            pending_request.response.set_result(result)
            self._finalize_request_and_cleanup(pending_request)

    def disconnect(self) -> None:
        self._init_connection_required = True

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

        if mtproto := self._mtproto:
            mtproto.close()

        if mtproto_loop := self._mtproto_loop_task:
            mtproto_loop.cancel()

        while not self._write_queue.empty():
            self._write_queue.get_nowait().finalize()

        self._mtproto_loop_task = None

    def __del__(self) -> None:
        if self._mtproto_loop_task is not None:
            logging.critical("client %d not disconnected", id(self))
