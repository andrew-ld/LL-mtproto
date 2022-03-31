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
            response.set_exception(InterruptedError())

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
        "_pending_ping_request",
        "_stable_seqno",
        "_updates_queue",
        "_no_updates"
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
    _pending_ping_request: asyncio.TimerHandle | None
    _updates_queue: asyncio.Queue[_Update | None]
    _no_updates: bool

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
        self._pending_ping_request = None
        self._updates_queue = asyncio.Queue()
        self._no_updates = no_updates
        self._mtproto = MTProto(self._datacenter.address, self._datacenter.port, self._datacenter.rsa, self._auth_key)

    async def get_update(self) -> _Update | None:
        await self._start_mtproto_loop_if_needed()
        return await self._updates_queue.get()

    async def rpc_call(self, message: dict[str, any]) -> Structure:
        if "_cons" not in message:
            raise RuntimeError("`_cons` attribute is required in message object")

        pending_request = _PendingRequest(self._loop, message)
        return await self._rpc_call(pending_request)

    async def _rpc_call(self, pending_request: _PendingRequest, no_response: bool = False) -> Structure | None:
        pending_request.retries += 1

        await self._start_mtproto_loop_if_needed()
        await self._flush_msgids_to_ack_if_needed()

        seqno = self._get_next_odd_seqno()

        message_id, write_future = self._mtproto.write(seqno, **pending_request.request)
        constructor = pending_request.request["_cons"]

        logging.debug("sending message (%s) %d to mtproto", constructor, message_id)

        if cleaner := pending_request.cleaner:
            cleaner.cancel()

        pending_request.cleaner = self._loop.call_later(120, self._cancel_pending_request, message_id)

        self._pending_requests[message_id] = pending_request

        try:
            await asyncio.wait_for(write_future, 120)
        except (OSError, asyncio.CancelledError, KeyboardInterrupt):
            self._cancel_pending_request(message_id)

        if not no_response:
            await self._start_mtproto_loop_if_needed()
            return await asyncio.wait_for(pending_request.response, 600)

    async def _start_mtproto_loop(self):
        self._cancel_pending_futures()

        if mtproto_loop := self._mtproto_loop_task:
            mtproto_loop.cancel()

        if mtproto_link := self._mtproto:
            mtproto_link.stop()

        logging.debug("connecting to Telegram at %s", self._datacenter)

        self._mtproto_loop_task = self._loop.create_task(self._mtproto_loop())
        await self._create_new_ping_request()

    def _create_new_ping_request_sync(self):
        self._loop.create_task(self._create_new_ping_request())

    async def _create_new_ping_request(self):
        random_ping_id = random.randrange(-2 ** 63, 2 ** 63)

        pending_request = _PendingRequest(self._loop, dict(_cons="ping", ping_id=random_ping_id))
        self._pending_pongs[random_ping_id] = self._loop.call_later(10, self.disconnect)

        await self._rpc_call(pending_request, no_response=True)

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
            except:
                logging.error("failure while read message from mtproto: %s", traceback.format_exc())
                self._cancel_pending_futures()
                break

            logging.debug("received message %d from mtproto", message.msg_id)

            try:
                await self._process_telegram_message(message)
                await self._flush_msgids_to_ack_if_needed()
            except:
                logging.error("failure while process message from mtproto: %s", traceback.format_exc())

    def _cancel_pending_futures(self):
        self._updates_queue.put_nowait(None)

        self._cancel_pending_pongs()
        self._cancel_pending_requests()

        if pending_ping_request := self._pending_ping_request:
            pending_ping_request.cancel()

        self._pending_ping_request = None

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

        elif body == "pong":
            self._process_pong(body)

        elif body == "bad_server_salt":
            await self._process_bad_server_salt(body)

        elif body == "bad_msg_notification" and body.error_code == 32:
            await self._process_bad_msg_notification_msg_seqno_too_low(body)

        elif body == "new_session_created":
            await self._process_new_session_created(body)

    async def _process_new_session_created(self, body: Structure):
        self._mtproto.set_server_salt(body.server_salt)

        bad_requests = dict((i, r) for i, r in self._pending_requests.items() if i < body.first_msg_id)

        for bad_msg_id, bad_request in bad_requests.items():
            self._pending_requests.pop(bad_msg_id, None)
            await self._rpc_call(bad_request, no_response=True)

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
        logging.debug("updating salt: %d", body.new_server_salt)

        if bad_request := self._pending_requests.pop(body.bad_msg_id, False):
            await self._rpc_call(bad_request, no_response=True)
        else:
            logging.debug("bad_msg_id %d not found", body.bad_msg_id)

    async def _process_bad_msg_notification_msg_seqno_too_low(self, body: Structure):
        self._seqno_increment = min(2 ** 31 - 1, self._seqno_increment << 1)
        self._last_seqno += self._seqno_increment

        logging.debug("updating seqno by %d to %d", self._seqno_increment, self._last_seqno)

        if bad_request := self._pending_requests.pop(body.bad_msg_id, False):
            await self._rpc_call(bad_request, no_response=True)
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
                await self._rpc_call(pending_request, no_response=True)

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
