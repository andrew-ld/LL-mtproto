import asyncio
import logging
import random
import time
import traceback
import typing

from . import RpcError
from .constants import TelegramDatacenter, TelegramDatacenterInfo
from .network import mtproto
from .network.mtproto import AuthKey, MTProto
from .tl.tl import Structure

__all__ = ("_Update", "Client")


class _PendingRequest:
    __slots__ = ("response", "request", "cleaner", "retries")

    response: asyncio.Future[Structure]
    request: dict
    cleaner: asyncio.TimerHandle | None
    retries: int

    def __init__(self, loop: asyncio.AbstractEventLoop, message: dict):
        self.response = loop.create_future()
        self.request = message
        self.cleaner = None
        self.retries = 0

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
        "_seq_no",
        "_mtproto",
        "_loop",
        "_msgids_to_ack",
        "_last_time_acks_flushed",
        "_last_seqno",
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

    _seq_no: int
    _mtproto: mtproto.MTProto
    _loop: asyncio.AbstractEventLoop
    _msgids_to_ack: list[int]
    _last_time_acks_flushed: float
    _last_seqno: int
    _stable_seqno: bool
    _seqno_increment: int
    _mtproto_loop_task: asyncio.Task | None
    _pending_requests: dict[int, _PendingRequest]
    _pending_pongs: dict[int, asyncio.TimerHandle]
    _datacenter: TelegramDatacenterInfo
    _auth_key: AuthKey
    _pending_ping: asyncio.TimerHandle | None
    _updates_queue: asyncio.Queue[_Update | None]
    _no_updates: bool
    _pending_future_salt: asyncio.TimerHandle | None

    def __init__(self, datacenter: TelegramDatacenter, auth_key: AuthKey, no_updates: bool = False):
        self._seq_no = -1
        self._loop = asyncio.get_event_loop()
        self._msgids_to_ack = []
        self._last_time_acks_flushed = time.time()
        self._last_seqno = 0
        self._stable_seqno = False
        self._seqno_increment = 1
        self._mtproto_loop_task = None
        self._pending_requests = dict()
        self._pending_pongs = dict()
        self._datacenter = typing.cast(TelegramDatacenterInfo, datacenter.value)
        self._auth_key = auth_key
        self._pending_ping = None
        self._updates_queue = asyncio.Queue()
        self._no_updates = no_updates
        self._pending_future_salt = None
        self._mtproto = MTProto(self._datacenter.address, self._datacenter.port, self._datacenter.rsa, self._auth_key)

    async def get_update(self) -> _Update | None:
        await self._start_mtproto_loop_if_needed()
        return await self._updates_queue.get()

    async def rpc_call(self, message: dict[str, any]) -> Structure:
        if "_cons" not in message:
            raise RuntimeError("`_cons` attribute is required in message object")

        pending_request = _PendingRequest(self._loop, message)
        return await self._rpc_call(pending_request, wait_result=True)

    async def _rpc_call(self, request: _PendingRequest, *, wait_result: bool) -> Structure | None:
        request.retries += 1

        if wait_result:
            await self._start_mtproto_loop_if_needed()

        seqno = self._get_next_odd_seqno()

        message_id, write_future = self._mtproto.write(seqno, **request.request)
        constructor = request.request["_cons"]

        logging.debug("sending message (%s) %d to mtproto", constructor, message_id)

        if cleaner := request.cleaner:
            cleaner.cancel()

        request.cleaner = self._loop.call_later(120, self._cancel_pending_request, message_id)

        self._pending_requests[message_id] = request

        try:
            await asyncio.wait_for(write_future, 120)
        except (OSError, KeyboardInterrupt):
            self._cancel_pending_request(message_id)

        if wait_result:
            await self._start_mtproto_loop_if_needed()
            return await asyncio.wait_for(request.response, 600)

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

    async def _create_future_salt_request(self):
        pending_request = _PendingRequest(self._loop, dict(_cons="get_future_salts", num=2))
        await self._rpc_call(pending_request, wait_result=False)

    async def _create_ping_request(self):
        random_ping_id = random.randrange(-2 ** 63, 2 ** 63)

        pending_request = _PendingRequest(self._loop, dict(_cons="ping", ping_id=random_ping_id))
        self._pending_pongs[random_ping_id] = self._loop.call_later(10, self.disconnect)

        await self._rpc_call(pending_request, wait_result=False)

    def _get_next_odd_seqno(self) -> int:
        self._last_seqno = ((self._last_seqno + 1) // 2) * 2 + 1
        return self._last_seqno

    def _get_next_even_seqno(self) -> int:
        self._last_seqno = (self._last_seqno // 2 + 1) * 2
        return self._last_seqno

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

            logging.debug("received message %d from mtproto", message.msg_id)

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

    async def _process_telegram_message_body(self, body: Structure):
        if body == "rpc_result":
            await self._process_rpc_result(body)

        elif body == "updates" and not self._no_updates:
            await self._process_updates(body)

        elif body == "bad_server_salt":
            await self._process_bad_server_salt(body)

        elif body == "bad_msg_notification" and body.error_code == 32:
            await self._process_bad_msg_notification_msg_seqno_too_low(body)

        elif body == "new_session_created":
            await self._process_new_session_created(body)

        elif body == "pong":
            self._process_pong(body)

        elif body == "future_salts":
            self._process_future_salts(body)

    def _process_future_salts(self, body: Structure):
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

    async def _process_new_session_created(self, body: Structure):
        self._auth_key.server_salt = body.server_salt

        bad_requests = dict((i, r) for i, r in self._pending_requests.items() if i < body.first_msg_id)

        for bad_msg_id, bad_request in bad_requests.items():
            self._pending_requests.pop(bad_msg_id, None)
            await self._rpc_call(bad_request, wait_result=False)

    async def _process_updates(self, body: Structure):
        users = body.users
        chats = body.chats

        for update in body.updates:
            await self._updates_queue.put(_Update(users, chats, update))

    def _process_pong(self, pong: Structure):
        logging.debug("pong message: %d", pong.ping_id)

        self._cancel_pending_pong(pong.ping_id)

        if pending_request := self._pending_requests.pop(pong.msg_id, False):
            pending_request.response.set_result(pong)
            pending_request.finalize()

        if pending_ping_request := self._pending_ping:
            pending_ping_request.cancel()

        self._pending_ping = self._loop.call_later(10, lambda: self._loop.create_task(self._create_ping_request()))

    async def _acknowledge_telegram_message(self, message: Structure):
        if message.seqno % 2 == 1:
            self._msgids_to_ack.append(message.msg_id)
            await self._flush_msgids_to_ack()

    async def _flush_msgids_to_ack(self):
        self._last_time_acks_flushed = time.time()

        if not self._msgids_to_ack or not self._stable_seqno:
            return

        msgids_to_ack = self._msgids_to_ack[:1024]
        seqno = self._get_next_even_seqno()

        _, write_future = self._mtproto.write(seqno, _cons="msgs_ack", msg_ids=msgids_to_ack)
        await asyncio.wait_for(write_future, 120)

        any(map(self._msgids_to_ack.remove, msgids_to_ack))

    def _update_last_seqno_from_incoming_message(self, message: Structure):
        self._last_seqno = max(self._last_seqno, message.seqno)

    async def _process_bad_server_salt(self, body: Structure):
        if self._auth_key.server_salt:
            self._stable_seqno = False

        self._auth_key.server_salt = body.new_server_salt
        logging.debug("updating salt: %d", body.new_server_salt)

        if bad_request := self._pending_requests.pop(body.bad_msg_id, False):
            await self._rpc_call(bad_request, wait_result=False)
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

    async def _process_bad_msg_notification_msg_seqno_too_low(self, body: Structure):
        self._seqno_increment = min(2 ** 31 - 1, self._seqno_increment << 1)
        self._last_seqno += self._seqno_increment

        logging.debug("updating seqno by %d to %d", self._seqno_increment, self._last_seqno)

        if bad_request := self._pending_requests.pop(body.bad_msg_id, False):
            await self._rpc_call(bad_request, wait_result=False)
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

    async def _process_rpc_result(self, body: Structure):
        self._stable_seqno = True
        self._seqno_increment = 1

        if pending_request := self._pending_requests.pop(body.req_msg_id, False):
            if body.result == "gzip_packed":
                result = body.result.packed_data
            else:
                result = body.result

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
