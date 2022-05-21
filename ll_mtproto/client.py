import asyncio
import logging
import random
import time
import traceback
import typing

from . import RpcError
from .network.datacenter_info import DatacenterInfo
from .network import mtproto
from .network.mtproto import AuthKey, MTProto
from .typed import TlMessageBody, Structure

__all__ = ("_Update", "Client")

_SeqNoGenerator = typing.Callable[[], int]


class _PendingRequest:
    __slots__ = ("response", "request", "cleaner", "retries", "next_seq_no")

    response: asyncio.Future[TlMessageBody]
    request: dict[str, any]
    cleaner: asyncio.TimerHandle | None
    retries: int
    next_seq_no: _SeqNoGenerator

    def __init__(self, loop: asyncio.AbstractEventLoop, message: dict[str, any], seq_no_func: _SeqNoGenerator):
        self.response = loop.create_future()
        self.request = message
        self.cleaner = None
        self.retries = 0
        self.next_seq_no = seq_no_func

    def finalize(self):
        if not (response := self.response).done():
            response.set_exception(ConnectionResetError())

        if cleaner := self.cleaner:
            cleaner.cancel()

        self.cleaner = None
        self.response.exception()


class _Update:
    __slots__ = ("users", "chats", "update")

    users: list[Structure]
    chats: list[Structure]
    update: Structure

    def __init__(self, users: list[Structure], chats: list[Structure], update: Structure):
        self.users = users
        self.chats = chats
        self.update = update


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
        "_pending_future_salt"
    )

    _mtproto: mtproto.MTProto
    _loop: asyncio.AbstractEventLoop
    _msgids_to_ack: list[int]
    _last_time_acks_flushed: float
    _stable_seqno: bool
    _seqno_increment: int
    _mtproto_loop_task: asyncio.Task | None
    _pending_requests: dict[int, _PendingRequest]
    _pending_pongs: dict[int, asyncio.TimerHandle]
    _datacenter: DatacenterInfo
    _auth_key: AuthKey
    _pending_ping: asyncio.TimerHandle | None
    _updates_queue: asyncio.Queue[_Update | None]
    _no_updates: bool
    _pending_future_salt: asyncio.TimerHandle | None

    def __init__(self, datacenter: DatacenterInfo, auth_key: AuthKey, no_updates: bool = False):
        self._loop = asyncio.get_event_loop()
        self._msgids_to_ack = []
        self._last_time_acks_flushed = time.time()
        self._stable_seqno = False
        self._seqno_increment = 1
        self._mtproto_loop_task = None
        self._pending_requests = dict()
        self._pending_pongs = dict()
        self._auth_key = auth_key
        self._pending_ping = None
        self._updates_queue = asyncio.Queue()
        self._no_updates = no_updates
        self._pending_future_salt = None
        self._datacenter = datacenter
        self._mtproto = MTProto(datacenter, auth_key)

    async def get_update(self) -> _Update | None:
        if self._no_updates:
            raise RuntimeError("the updates queue is always empty if no_updates has been set to true.")

        await self._start_mtproto_loop_if_needed()
        return await self._updates_queue.get()

    async def rpc_call_multi(self, payloads: typing.Iterable[dict[str, any]]) -> tuple[TlMessageBody | BaseException]:
        messages = []
        messages_ids = []
        responses = []

        await self._start_mtproto_loop_if_needed()

        for payload in payloads:
            request = _PendingRequest(self._loop, payload, self._get_next_odd_seqno)
            request_message, request_message_id = self._mtproto.box_message(request.next_seq_no(), **payload)

            self._pending_requests[request_message_id] = request

            messages.append(request_message)
            messages_ids.append(request_message_id)
            responses.append(request.response)

        if not messages:
            raise ValueError("this method expects the `payloads` iterator to return at least one element")

        container_message = dict(_cons="msg_container", messages=messages)
        container_request = _PendingRequest(self._loop, container_message, self._get_next_even_seqno)
        container_message_id = await self._rpc_call(container_request, wait_result=True)

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

    async def rpc_call(self, payload: dict[str, any]) -> TlMessageBody:
        pending_request = _PendingRequest(self._loop, payload, self._get_next_odd_seqno)
        await self._rpc_call(pending_request, wait_result=True)
        return await pending_request.response

    async def _rpc_call(self, request: _PendingRequest, *, wait_result: bool) -> int:
        request.retries += 1

        if wait_result:
            await self._start_mtproto_loop_if_needed()

        message, message_id = self._mtproto.box_message(request.next_seq_no(), **request.request)

        logging.debug("sending message (%s) %d to mtproto", request.request["_cons"], message_id)

        if cleaner := request.cleaner:
            cleaner.cancel()

        request.cleaner = self._loop.call_later(120, self._cancel_pending_request, message_id)

        self._pending_requests[message_id] = request

        try:
            await asyncio.wait_for(self._mtproto.write(message), 120)
        except (OSError, KeyboardInterrupt):
            self._cancel_pending_request(message_id)

        if wait_result:
            await self._start_mtproto_loop_if_needed()

        return message_id

    async def _start_mtproto_loop(self):
        self._cancel_pending_futures()

        if mtproto_loop := self._mtproto_loop_task:
            mtproto_loop.cancel()

        if mtproto_link := self._mtproto:
            mtproto_link.stop()

        logging.debug("connecting to Telegram at %s", self._datacenter)

        self._mtproto_loop_task = self._loop.create_task(self._mtproto_loop())

        await self._create_ping_request()
        await self._create_future_salt_request()
        await self._create_init_request()

    async def _create_init_request(self):
        if self._no_updates:
            message = dict(_cons="help.getConfig")
            message = dict(_cons="invokeWithoutUpdates", _wrapped=message)
        else:
            message = dict(_cons="updates.getState")

        message = dict(_cons="invokeWithLayer", _wrapped=message, layer=self._datacenter.schema.layer)

        get_state_request = _PendingRequest(self._loop, message, self._get_next_odd_seqno)
        await self._rpc_call(get_state_request, wait_result=False)

    async def _create_future_salt_request(self):
        get_future_salts_message = dict(_cons="get_future_salts", num=2)
        get_future_salts_request = _PendingRequest(self._loop, get_future_salts_message, self._get_next_odd_seqno)

        await self._rpc_call(get_future_salts_request, wait_result=False)

        if pending_future_salt := self._pending_future_salt:
            pending_future_salt.cancel()

        self._pending_future_salt = self._loop.call_later(
            30,
            lambda: self._loop.create_task(self._create_future_salt_request()))

    async def _create_ping_request(self):
        random_ping_id = random.randrange(-2 ** 63, 2 ** 63)
        self._pending_pongs[random_ping_id] = self._loop.call_later(10, self.disconnect)

        ping_message = dict(_cons="ping", ping_id=random_ping_id)
        ping_request = _PendingRequest(self._loop, ping_message, self._get_next_odd_seqno)

        await self._rpc_call(ping_request, wait_result=False)

    def _get_next_odd_seqno(self) -> int:
        self._auth_key.seq_no = ((self._auth_key.seq_no + 1) // 2) * 2 + 1
        return self._auth_key.seq_no

    def _get_next_even_seqno(self) -> int:
        self._auth_key.seq_no = (self._auth_key.seq_no // 2 + 1) * 2
        return self._auth_key.seq_no

    def _cancel_pending_pongs(self):
        for pending_pong in self._pending_pongs.values():
            pending_pong.cancel()

        self._pending_pongs.clear()

    def _cancel_pending_requests(self):
        for pending_request in self._pending_requests.values():
            pending_request.finalize()

        self._pending_requests.clear()

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
                break
            except:
                logging.error("failure while read message from mtproto: %s", traceback.format_exc())
                break

            logging.debug("received message (%s) %d from mtproto", message.body.constructor_name, message.msg_id)

            try:
                await self._process_telegram_message(message)
                await self._flush_msgids_to_ack_if_needed()
            except (KeyboardInterrupt, asyncio.CancelledError):
                break
            except:
                logging.error("failure while process message from mtproto: %s", traceback.format_exc())

        self._cancel_pending_futures()

    def _cancel_pending_futures(self):
        self._updates_queue.put_nowait(None)

        self._cancel_pending_pongs()
        self._cancel_pending_requests()

        if pending_future_salt := self._pending_future_salt:
            pending_future_salt.cancel()

        self._pending_future_salt = None

        if pending_ping_request := self._pending_ping:
            pending_ping_request.cancel()

        self._pending_ping = None

    async def _start_mtproto_loop_if_needed(self):
        if mtproto_loop_task := self._mtproto_loop_task:
            if mtproto_loop_task.done():
                await self._start_mtproto_loop()
        else:
            await self._start_mtproto_loop()

    async def _flush_msgids_to_ack_if_needed(self):
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
        match body.constructor_name:
            case "rpc_result":
                await self._process_rpc_result(body)

            case "updates":
                await self._process_updates(body)

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

            salt_expire = min(max(valid_salt.valid_until - body.now + 1, 1), 1801)

            self._pending_future_salt = self._loop.call_later(
                salt_expire,
                lambda: self._loop.create_task(self._create_future_salt_request()))

            logging.debug("scheduling get_future_salts, current salt is valid for %i seconds", salt_expire)

    async def _process_new_session_created(self, body: TlMessageBody):
        self._auth_key.server_salt = body.server_salt

        bad_requests = dict((i, r) for i, r in self._pending_requests.items() if i < body.first_msg_id)

        for bad_msg_id, bad_request in bad_requests.items():
            self._pending_requests.pop(bad_msg_id, None)
            await self._rpc_call(bad_request, wait_result=False)

    async def _process_updates(self, body: TlMessageBody):
        if self._no_updates:
            return

        users = body.users
        chats = body.chats

        for update in body.updates:
            await self._updates_queue.put(_Update(users, chats, update))

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
        msgids_to_ack_request = _PendingRequest(self._loop, msgids_to_ack_message, self._get_next_even_seqno)
        msgids_to_ack_message_id = await self._rpc_call(msgids_to_ack_request, wait_result=False)

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
            await self._rpc_call(bad_request, wait_result=False)
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
            await self._rpc_call(bad_request, wait_result=False)
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

            if result == "auth.authorization":
                await self._create_init_request()

            if result == "rpc_error" and result.error_code >= 500 and pending_request.retries < 5:
                logging.debug("rpc_error with 5xx status `%r` for request %d", result, body.req_msg_id)
                await self._rpc_call(pending_request, wait_result=False)

            elif result == "rpc_error":
                pending_request.response.set_exception(RpcError(result.error_code, result.error_message))
                pending_request.finalize()

            else:
                pending_request.response.set_result(result)
                pending_request.finalize()

    def disconnect(self):
        self._cancel_pending_futures()

        if mtproto_loop := self._mtproto_loop_task:
            mtproto_loop.cancel()

        if mtproto_link := self._mtproto:
            mtproto_link.stop()

        self._mtproto_loop_task = None

    def __del__(self):
        if self._mtproto_loop_task is not None:
            logging.critical("client %d not disconnected", id(self))
