import asyncio
import logging
import random
import time
import traceback
import typing

from . import PendingRequest, Update
from . import ConnectionInfo
from ..network import mtproto, DatacenterInfo
from ..crypto import AuthKey
from ..network.mtproto import MTProto
from ..tl import tl
from ..typed import TlMessageBody, Structure, RpcError, TlRequestBody

__all__ = ("Client",)


class Client:
    __slots__ = (
        "_mtproto",
        "_loop",
        "_msgids_to_ack",
        "_last_time_acks_flushed",
        "_seqno_increment",
        "_mtproto_loop_task",
        "_pending_requests",
        "_pending_pongs",
        "_datacenter",
        "_auth_key",
        "_pending_ping",
        "_stable_seqno",
        "_updates_queue",
        "_no_updates",
        "_pending_future_salt",
        "_layer_init_info",
        "_layer_init_required"
    )

    _mtproto: mtproto.MTProto
    _loop: asyncio.AbstractEventLoop
    _msgids_to_ack: list[int]
    _last_time_acks_flushed: float
    _stable_seqno: bool
    _seqno_increment: int
    _mtproto_loop_task: asyncio.Task | None
    _pending_requests: dict[int, PendingRequest]
    _pending_pongs: dict[int, asyncio.TimerHandle]
    _datacenter: DatacenterInfo
    _auth_key: AuthKey
    _pending_ping: asyncio.TimerHandle | None
    _updates_queue: asyncio.Queue[Update | None]
    _no_updates: bool
    _pending_future_salt: asyncio.TimerHandle | None
    _layer_init_info: ConnectionInfo
    _layer_init_required: bool

    def __init__(self, datacenter: DatacenterInfo, key: AuthKey, info: ConnectionInfo, no_updates: bool = False):
        self._loop = asyncio.get_event_loop()
        self._msgids_to_ack = []
        self._last_time_acks_flushed = time.time()
        self._stable_seqno = False
        self._seqno_increment = 1
        self._mtproto_loop_task = None
        self._pending_requests = dict()
        self._pending_pongs = dict()
        self._auth_key = key
        self._pending_ping = None
        self._updates_queue = asyncio.Queue()
        self._no_updates = no_updates
        self._pending_future_salt = None
        self._datacenter = datacenter
        self._mtproto = MTProto(datacenter, key)
        self._layer_init_info = info
        self._layer_init_required = True

    async def get_update(self) -> Update | None:
        if self._no_updates:
            raise RuntimeError("the updates queue is always empty if no_updates has been set to true.")

        await self._start_mtproto_loop_if_needed()
        return await self._updates_queue.get()

    async def rpc_call_multi(self, payloads: typing.Iterable[TlRequestBody]) -> tuple[TlMessageBody | BaseException]:
        messages = []
        messages_ids = []
        responses = []

        await self._start_mtproto_loop_if_needed()

        if self._layer_init_required:
            await self.rpc_call(dict(_cons="help.getConfig"))

        for payload in payloads:
            request = PendingRequest(self._loop, payload, self._get_next_odd_seqno, True)
            request_message, request_message_id = self._mtproto.box_message(request.next_seq_no(), **payload)

            self._pending_requests[request_message_id] = request

            messages.append(request_message)
            messages_ids.append(request_message_id)
            responses.append(request.response)

        if not messages:
            raise ValueError("this method expects the `payloads` iterator to return at least one element")

        container_message = dict(_cons="msg_container", messages=messages)
        container_request = PendingRequest(self._loop, container_message, self._get_next_even_seqno, False)
        container_message_id = await self._rpc_call(container_request, parent_is_waiting=True)

        await asyncio.wait((*responses, container_request.response), return_when=asyncio.FIRST_COMPLETED)

        container_request_exception: False | BaseException

        if (container_request_response := container_request.response).done():
            container_request_exception = container_request_response.exception()
        else:
            container_request_exception = False

        if pending_container_request := self._pending_requests.pop(container_message_id, False):
            pending_container_request.finalize()

        if container_request_exception:
            any(map(self._cancel_pending_request, messages_ids))
            raise container_request_exception from container_request_exception

        results = await asyncio.gather(*responses, return_exceptions=True)

        return typing.cast(tuple[TlMessageBody | BaseException], results)

    async def rpc_call(self, payload: TlRequestBody) -> TlMessageBody:
        pending_request = PendingRequest(self._loop, payload, self._get_next_odd_seqno, True)
        await self._rpc_call(pending_request, parent_is_waiting=True)
        return await pending_request.response

    async def _rpc_call(self, request: PendingRequest, *, parent_is_waiting: bool) -> int:
        request.retries += 1

        if parent_is_waiting:
            await self._start_mtproto_loop_if_needed()

        if request.allow_container:
            layer_init_boxing_required = self._layer_init_required
        else:
            layer_init_boxing_required = False

        request_body = request.request

        if layer_init_boxing_required:
            request_body = self._wrap_request_in_layer_init(request_body)
            self._layer_init_required = False

        message, message_id = self._mtproto.box_message(request.next_seq_no(), **request_body)

        logging.debug("sending message (%s) %d to mtproto", request.request["_cons"], message_id)

        if cleaner := request.cleaner:
            cleaner.cancel()

        request.cleaner = self._loop.call_later(120, self._cancel_pending_request, message_id)

        self._pending_requests[message_id] = request

        try:
            await self._write_mtproto_socket(message, 120, parent_is_waiting)
        except (KeyboardInterrupt, asyncio.CancelledError):
            self._cancel_pending_request(message_id)
            raise
        except:
            logging.error("failure while write tl payload to mtproto: %s", traceback.format_exc())
            self.disconnect()

        return message_id

    def _wrap_request_in_layer_init(self, message: TlRequestBody) -> TlRequestBody:
        message = dict(_cons="initConnection", _wrapped=message, **self._layer_init_info.dict())
        message = dict(_cons="invokeWithLayer", _wrapped=message, layer=self._datacenter.schema.layer)
        return message

    async def _write_mtproto_socket(self, message: tl.Value, timeout: int, parent_is_waiting: bool):
        write_coro = self._mtproto.write(message)

        if parent_is_waiting:
            await asyncio.wait_for(write_coro, timeout)
        else:
            await write_coro

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
        get_future_salts_request = PendingRequest(self._loop, get_future_salts_message, self._get_next_odd_seqno, False)

        if pending_future_salt := self._pending_future_salt:
            pending_future_salt.cancel()

        self._pending_future_salt = self._loop.call_later(
            30,
            lambda: self._loop.create_task(self._create_future_salt_request()))

        await self._rpc_call(get_future_salts_request, parent_is_waiting=False)

    async def _create_ping_request(self):
        random_ping_id = random.randrange(-2 ** 63, 2 ** 63)
        self._pending_pongs[random_ping_id] = self._loop.call_later(10, self.disconnect)

        ping_message = dict(_cons="ping", ping_id=random_ping_id)
        ping_request = PendingRequest(self._loop, ping_message, self._get_next_odd_seqno, False)

        await self._rpc_call(ping_request, parent_is_waiting=False)

    def _get_next_odd_seqno(self) -> int:
        self._auth_key.seq_no = ((self._auth_key.seq_no + 1) // 2) * 2 + 1
        return self._auth_key.seq_no

    def _get_next_even_seqno(self) -> int:
        self._auth_key.seq_no = (self._auth_key.seq_no // 2 + 1) * 2
        return self._auth_key.seq_no

    def _cancel_pending_pong(self, ping_id: int):
        if pending_pong := self._pending_pongs.pop(ping_id, False):
            pending_pong.cancel()

    def _cancel_pending_request(self, msg_id: int):
        if pending_request := self._pending_requests.pop(msg_id, False):
            pending_request.finalize()

    async def _mtproto_loop(self):
        while mtproto_link := self._mtproto:
            try:
                message = await mtproto_link.read()
            except (KeyboardInterrupt, asyncio.CancelledError, GeneratorExit):
                raise
            except:
                logging.error("failure while read message from mtproto: %s", traceback.format_exc())
                self.disconnect()
                break

            logging.debug("received message (%s) %d from mtproto", message.body.constructor_name, message.msg_id)

            try:
                await self._process_telegram_message(message)
                await self._flush_msgids_to_ack_if_needed()
            except (KeyboardInterrupt, asyncio.CancelledError):
                raise
            except:
                logging.error("failure while process message from mtproto: %s", traceback.format_exc())

    async def _start_mtproto_loop_if_needed(self):
        if mtproto_loop_task := self._mtproto_loop_task:
            if mtproto_loop_task.done():
                await self._start_mtproto_loop()
        else:
            await self._start_mtproto_loop()

    async def _flush_msgids_to_ack_if_needed(self):
        if not self._msgids_to_ack:
            return

        if len(self._msgids_to_ack) >= 32 or (time.time() - self._last_time_acks_flushed) > 10:
            await self._flush_msgids_to_ack()

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
        if pending_request := self._pending_requests.pop(body.req_msg_id, False):
            pending_request.response.set_result(body)
            pending_request.finalize()

    def _process_msg_new_detailed_info(self, body: TlMessageBody):
        if pending_request := self._pending_requests.pop(body.answer_msg_id, False):
            pending_request.finalize()

    def _process_msg_detailed_info(self, body: TlMessageBody):
        self._process_msg_new_detailed_info(body)
        self._msgids_to_ack.append(body.msg_id)

    def _process_future_salts(self, body: TlMessageBody):
        if pending_request := self._pending_requests.pop(body.req_msg_id, False):
            pending_request.response.set_result(body)
            pending_request.finalize()

        if pending_future_salt := self._pending_future_salt:
            pending_future_salt.cancel()

        if valid_salt := next((salt for salt in body.salts if salt.valid_since <= body.now), False):
            self._auth_key.server_salt = valid_salt.salt

            salt_expire = max((valid_salt.valid_until - body.now) - 1800, 10)

            self._pending_future_salt = self._loop.call_later(
                salt_expire,
                lambda: self._loop.create_task(self._create_future_salt_request()))

            logging.debug("scheduling get_future_salts, current salt is valid for %i seconds", salt_expire)

    async def _process_new_session_created(self, body: TlMessageBody):
        self._auth_key.server_salt = body.server_salt

        bad_requests = dict((i, r) for i, r in self._pending_requests.items() if i < body.first_msg_id)

        for bad_msg_id, bad_request in bad_requests.items():
            self._pending_requests.pop(bad_msg_id, None)
            await self._rpc_call(bad_request, parent_is_waiting=False)

    async def _process_updates(self, body: TlMessageBody):
        if self._no_updates:
            return

        users = body.users
        chats = body.chats

        for update in body.updates:
            await self._updates_queue.put(Update(users, chats, update))

    def _process_pong(self, pong: TlMessageBody):
        logging.debug("pong message: %d", pong.ping_id)

        self._cancel_pending_pong(pong.ping_id)

        if pending_request := self._pending_requests.pop(pong.msg_id, False):
            pending_request.response.set_result(pong)
            pending_request.finalize()

        if pending_ping_request := self._pending_ping:
            pending_ping_request.cancel()

        self._pending_ping = self._loop.call_later(30, lambda: self._loop.create_task(self._create_ping_request()))

    async def _acknowledge_telegram_message(self, message: Structure):
        if message.seqno % 2 == 1:
            self._msgids_to_ack.append(message.msg_id)
            await self._flush_msgids_to_ack()

    async def _flush_msgids_to_ack(self):
        self._last_time_acks_flushed = time.time()

        if not self._msgids_to_ack or not self._stable_seqno:
            return

        msgids_to_ack = self._msgids_to_ack[:1024]

        msgids_to_ack_message = dict(_cons="msgs_ack", msg_ids=msgids_to_ack)
        msgids_to_ack_request = PendingRequest(self._loop, msgids_to_ack_message, self._get_next_even_seqno, False)
        msgids_to_ack_message_id = await self._rpc_call(msgids_to_ack_request, parent_is_waiting=False)

        if pending_msgids_to_ack_request := self._pending_requests.pop(msgids_to_ack_message_id, False):
            pending_msgids_to_ack_request.finalize()

        any(map(self._msgids_to_ack.remove, msgids_to_ack))

    def _update_last_seqno_from_incoming_message(self, message: Structure):
        self._auth_key.seq_no = max(self._auth_key.seq_no, message.seqno)

    async def _process_bad_server_salt(self, body: TlMessageBody):
        if self._auth_key.server_salt:
            self._stable_seqno = False

        self._auth_key.server_salt = body.new_server_salt
        logging.debug("updating salt: %d", body.new_server_salt)

        if bad_request := self._pending_requests.pop(body.bad_msg_id, False):
            await self._rpc_call(bad_request, parent_is_waiting=False)
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

    async def _process_bad_msg_notification(self, body: TlMessageBody):
        if body.error_code == 32:
            await self._process_bad_msg_notification_msg_seqno_too_low(body)
        else:
            self._process_bad_msg_notification_reject_message(body)

    def _process_bad_msg_notification_reject_message(self, body: TlMessageBody):
        if bad_request := self._pending_requests.pop(body.bad_msg_id, False):
            bad_request.response.set_exception(RpcError(body.error_code, "BAD_MSG_NOTIFICATION"))
            bad_request.finalize()
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

    async def _process_bad_msg_notification_msg_seqno_too_low(self, body: TlMessageBody):
        self._seqno_increment = min(2 ** 31 - 1, self._seqno_increment << 1)
        self._auth_key.seq_no += self._seqno_increment

        logging.debug("updating seqno by %d to %d", self._seqno_increment, self._auth_key.seq_no)

        if bad_request := self._pending_requests.pop(body.bad_msg_id, False):
            await self._rpc_call(bad_request, parent_is_waiting=False)
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

    async def _process_rpc_result(self, body: TlMessageBody):
        self._stable_seqno = True
        self._seqno_increment = 1

        if pending_request := self._pending_requests.pop(body.req_msg_id, False):
            if body.result == "gzip_packed":
                result = body.result.packed_data
            else:
                result = body.result

            if result == "rpc_error" and result.error_code >= 500 and pending_request.retries < 5:
                logging.debug("rpc_error with 5xx status `%r` for request %d", result, body.req_msg_id)
                await self._rpc_call(pending_request, parent_is_waiting=False)

            elif result == "rpc_error":
                pending_request.response.set_exception(RpcError(result.error_code, result.error_message))
                pending_request.finalize()

            else:
                pending_request.response.set_result(result)
                pending_request.finalize()

    def disconnect(self):
        self._layer_init_required = True

        self._updates_queue.put_nowait(None)

        for pending_pong in self._pending_pongs.values():
            pending_pong.cancel()

        self._pending_pongs.clear()

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

        self._mtproto_loop_task = None

    def __del__(self):
        if self._mtproto_loop_task is not None:
            logging.critical("client %d not disconnected", id(self))
