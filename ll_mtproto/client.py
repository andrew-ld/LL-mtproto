import asyncio
import logging
import random
import time
import traceback
import typing

from .constants import TelegramDatacenter, _TelegramDatacenterInfo
from .network import mtproto
from .network.mtproto import AuthKey, MTProto
from .tl.tl import Structure

__all__ = ("_Update", "Client")


class _PendingRequest:
    __slots__ = ("response", "request", "cleaner")

    response: asyncio.Future[Structure]
    request: dict
    cleaner: asyncio.TimerHandle | None

    def __init__(self, loop: asyncio.AbstractEventLoop, message: dict):
        self.response = loop.create_future()
        self.request = message
        self.cleaner = None


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
        "_pending_ping_request",
        "_stable_seqno",
        "_updates_queue"
    )

    _seq_no: int
    _mtproto: mtproto.MTProto | None
    _loop: asyncio.AbstractEventLoop
    _msgids_to_ack: list[int]
    _last_time_acks_flushed: float
    _last_seqno: int
    _stable_seqno: bool
    _seqno_increment: int
    _mtproto_loop_task: asyncio.Task | None
    _pending_requests: dict[int, _PendingRequest]
    _pending_pongs: dict[int, asyncio.TimerHandle]
    _datacenter: _TelegramDatacenterInfo
    _auth_key: AuthKey
    _pending_ping_request: asyncio.TimerHandle | None
    _updates_queue: asyncio.Queue[_Update | None]

    def __init__(self, datacenter: TelegramDatacenter, auth_key: AuthKey):
        self._seq_no = -1
        self._mtproto = None
        self._loop = asyncio.get_event_loop()
        self._msgids_to_ack = []
        self._last_time_acks_flushed = time.time()
        self._last_seqno = 0
        self._stable_seqno = False
        self._seqno_increment = 1
        self._mtproto_loop_task = None
        self._pending_requests = dict()
        self._pending_pongs = dict()
        self._datacenter = typing.cast(_TelegramDatacenterInfo, datacenter.value)
        self._auth_key = auth_key
        self._pending_ping_request = None
        self._updates_queue = asyncio.Queue()

    async def get_update(self) -> _Update | None:
        await self._start_mtproto_loop_if_needed()
        return await self._updates_queue.get()

    async def rpc_call(self, message: dict[str, any]) -> Structure:
        if "_cons" not in message:
            raise RuntimeError("`_cons` attribute is required in message object")

        pending_request = _PendingRequest(self._loop, message)
        return await self._rpc_call(pending_request)

    async def _rpc_call(self, pending_request: _PendingRequest, no_response: bool = False) -> Structure | None:
        await self._start_mtproto_loop_if_needed()
        await self._flush_msgids_to_ack_if_needed()

        seqno = self._get_next_odd_seqno()

        message_id, write_future = self._mtproto.write(seqno, **pending_request.request)
        constructor = pending_request.request["_cons"]

        logging.log(logging.DEBUG, "sending message (%s) %d to mtproto", constructor, message_id)

        if no_response:
            pending_request.cleaner = self._loop.call_later(600, self._cancel_pending_request, message_id)

        self._pending_requests[message_id] = pending_request

        try:
            await asyncio.wait_for(write_future, 120)
        except (OSError, asyncio.CancelledError, KeyboardInterrupt):
            self._cancel_pending_request(message_id)

        if not no_response:
            return await asyncio.wait_for(pending_request.response, 600)

    async def _start_mtproto_loop(self):
        self._cancel_pending_futures()

        if self._mtproto is not None:
            self._mtproto_loop_task.cancel()
            self._mtproto.stop()

        logging.log(logging.DEBUG, "connecting to Telegram at %s", self._datacenter)

        self._mtproto = MTProto(self._datacenter.address, self._datacenter.port, self._datacenter.rsa, self._auth_key)

        self._mtproto_loop_task = self._loop.create_task(self._mtproto_loop())
        await self._create_new_ping_request()

    def _create_new_ping_request_sync(self):
        self._loop.create_task(self._create_new_ping_request())

    async def _create_new_ping_request(self):
        new_random_ping_id = random.randrange(-2 ** 63, 2 ** 63)
        seqno = self._get_next_odd_seqno()

        request = dict(_cons="ping", ping_id=new_random_ping_id)
        pending_request = _PendingRequest(self._loop, request)

        self._pending_pongs[new_random_ping_id] = self._loop.call_later(10, self.disconnect)

        message_id, write_future = self._mtproto.write(seqno, **request)
        self._pending_requests[message_id] = pending_request

        await asyncio.wait_for(write_future, 120)

    def _get_next_odd_seqno(self) -> int:
        self._last_seqno = ((self._last_seqno + 1) // 2) * 2 + 1
        return self._last_seqno

    def _get_next_even_seqno(self) -> int:
        self._last_seqno = (self._last_seqno // 2 + 1) * 2
        return self._last_seqno

    def _cancel_pending_pongs(self):
        for pending_pong_id in self._pending_pongs.keys():
            self._cancel_pending_pong(pending_pong_id, False)

        self._pending_pongs.clear()

    def _cancel_pending_requests(self):
        for pending_request_id in self._pending_requests.keys():
            self._cancel_pending_request(pending_request_id, False)

        self._pending_requests.clear()

    def _cancel_pending_pong(self, ping_id: int, remove: bool = True):
        if ping_id in self._pending_pongs:
            if remove:
                pending_pong = self._pending_pongs.pop(ping_id)
            else:
                pending_pong = self._pending_pongs[ping_id]

            pending_pong.cancel()

    def _cancel_pending_request(self, msg_id: int, remove: bool = True):
        if msg_id in self._pending_requests:
            if remove:
                pending_request = self._pending_requests.pop(msg_id)
            else:
                pending_request = self._pending_requests[msg_id]

            if not pending_request.response.done():
                pending_request.response.set_exception(InterruptedError())

            if pending_request.cleaner is not None:
                pending_request.cleaner.cancel()
                pending_request.cleaner = None

    async def _mtproto_loop(self):
        while self._mtproto:
            try:
                message = await self._mtproto.read()
            except:
                logging.log(logging.ERROR, "failure while read message from mtproto: %s", traceback.format_exc())
                self._cancel_pending_futures()
                break

            logging.log(logging.DEBUG, "received message %d from mtproto", message.msg_id)

            try:
                await self._process_telegram_message(message)
                await self._flush_msgids_to_ack_if_needed()
            except:
                logging.log(logging.ERROR, "failure while process message from mtproto: %s", traceback.format_exc())

    def _cancel_pending_futures(self):
        self._updates_queue.put_nowait(None)

        self._cancel_pending_pongs()
        self._cancel_pending_requests()

        if self._pending_ping_request is not None:
            self._pending_ping_request.cancel()

        self._pending_ping_request = None

    async def _start_mtproto_loop_if_needed(self):
        if self._mtproto is None or self._mtproto_loop_task.done():
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
            self._process_rpc_result(body)

        elif body == "pong":
            self._process_pong(body)

        elif body == "bad_server_salt":
            await self._process_bad_server_salt(body)

        elif body == "bad_msg_notification" and body.error_code == 32:
            await self._process_bad_msg_notification_msg_seqno_too_low(body)

        elif body == "updates":
            await self._process_updates(body)

    async def _process_updates(self, body: Structure):
        users = body.users
        chats = body.chats

        for update in body.updates:
            await self._updates_queue.put(_Update(users, chats, update))

    def _process_pong(self, pong: Structure):
        logging.log(logging.DEBUG, "pong message: %d", pong.ping_id)

        self._cancel_pending_pong(pong.ping_id)

        if pending_request := self._pending_requests.get(pong.msg_id, False):
            pending_request.response.set_result(pong)

        self._cancel_pending_request(pong.msg_id)

        if pending_ping_request := self._pending_ping_request:
            pending_ping_request.cancel()

        self._pending_ping_request = self._loop.call_later(10, self._create_new_ping_request_sync)

    async def _acknowledge_telegram_message(self, message: Structure):
        if message.seqno % 2 == 1:
            self._msgids_to_ack.append(message.msg_id)
            await self._flush_msgids_to_ack()

    async def _flush_msgids_to_ack(self):
        self._last_time_acks_flushed = time.time()

        if not self._msgids_to_ack or not self._stable_seqno:
            return

        seqno = self._get_next_even_seqno()
        _, write_future = self._mtproto.write(seqno, _cons="msgs_ack", msg_ids=self._msgids_to_ack)
        await asyncio.wait_for(write_future, 120)
        self._msgids_to_ack = []

    def _update_last_seqno_from_incoming_message(self, message: Structure):
        self._last_seqno = max(self._last_seqno, message.seqno)

    async def _process_bad_server_salt(self, body: Structure):
        if self._mtproto.get_server_salt() != 0:
            self._stable_seqno = False

        self._mtproto.set_server_salt(body.new_server_salt)
        logging.log(logging.DEBUG, "updating salt: %d", body.new_server_salt)

        if bad_request := self._pending_requests.pop(body.bad_msg_id, False):
            await self._rpc_call(bad_request, no_response=True)
        else:
            logging.log(logging.DEBUG, "bad_msg_id %d not found", body.bad_msg_id)

    async def _process_bad_msg_notification_msg_seqno_too_low(self, body: Structure):
        self._seqno_increment = min(2 ** 31 - 1, self._seqno_increment << 1)
        self._last_seqno += self._seqno_increment

        logging.log(logging.DEBUG, "updating seqno by %d to %d", self._seqno_increment, self._last_seqno)

        if bad_request := self._pending_requests.pop(body.bad_msg_id, False):
            await self._rpc_call(bad_request, no_response=True)
        else:
            logging.log(logging.DEBUG, "bad_msg_id %d not found", body.bad_msg_id)

    def _process_rpc_result(self, body: Structure):
        self._stable_seqno = True
        self._seqno_increment = 1

        if pending_request := self._pending_requests.get(body.req_msg_id, False):
            if body.result == "gzip_packed":
                result = body.result.packed_data
            else:
                result = body.result

            pending_request.response.set_result(result)

        self._cancel_pending_request(body.req_msg_id)

    def disconnect(self):
        self._cancel_pending_futures()

        if self._mtproto is not None:
            self._mtproto_loop_task.cancel()
            self._mtproto.stop()

        self._mtproto = None
        self._mtproto_loop_task = None

    def __del__(self):
        if self._mtproto is not None:
            logging.log(logging.CRITICAL, "client %d not disconnected", id(self))
