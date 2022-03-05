import asyncio
import logging
import time

from .localsettings import TELEGRAM_HOST, TELEGRAM_PORT, TELEGRAM_RSA
from .network import mtproto


class _PendingRequest:
    response: asyncio.Future
    request: dict

    def __init__(self, loop: asyncio.AbstractEventLoop, message: dict):
        self.response = loop.create_future()
        self.request = message


class Session:
    _seq_no: int
    _mtproto: mtproto.MTProto | None
    _loop: asyncio.AbstractEventLoop
    _msgids_to_ack: list[int]
    _last_time_acks_flushed: float
    _last_seqno: int
    _stable_seqno: bool
    _seqno_increment: int
    _mtproto_loop: asyncio.Task | None
    _mtproto_read_future: asyncio.Future | None
    _pending_requests: dict[int, _PendingRequest]
    _future_flood_wait: asyncio.Future | None
    _host: str
    _port: int
    _rsa: str
    _session: tuple[str, int] | None

    def __init__(self):
        self._seq_no = -1
        self._mtproto = None
        self._loop = asyncio.get_event_loop()
        self._msgids_to_ack = []
        self._last_time_acks_flushed = time.time()
        self._last_seqno = 0
        self._stable_seqno = False
        self._seqno_increment = 1
        self._mtproto_loop = None
        self._mtproto_read_future = None
        self._pending_requests = dict()
        self._future_flood_wait = None
        self._host = TELEGRAM_HOST
        self._port = TELEGRAM_PORT
        self._rsa = TELEGRAM_RSA
        self._session = None

    async def rpc_call(self, message):
        if self._mtproto is None:
            self.start_mtproto_loop()

        if "_cons" not in message:
            raise RuntimeError("`_cons` attribute is required in message object")

        pending_request = _PendingRequest(self._loop, message)
        return await self._rpc_call(pending_request)

    def _get_next_odd_seqno(self):
        self._last_seqno = ((self._last_seqno + 1) // 2) * 2 + 1
        return self._last_seqno

    def _get_next_even_seqno(self):
        self._last_seqno = (self._last_seqno // 2 + 1) * 2
        return self._last_seqno

    def start_mtproto_loop(self):
        if self._mtproto is not None:
            self._mtproto_loop.cancel()
            self._mtproto = None

        logging.log(logging.DEBUG, f"connecting to Telegram at {self._host}:{self._port:d}")

        self._mtproto_loop = self._loop.create_task(self.mtproto_loop())
        self._mtproto = mtproto.MTProto(self._host, self._port, self._rsa)

        if self._session is not None:
            self._mtproto.set_session(*self._session)

    def _delete_pending_request(self, msg_id):
        if msg_id in self._pending_requests:
            self._pending_requests[msg_id].response.set_result(dict(_cons="rpc_timeout"))

    async def _rpc_call(self, pending_request):
        self._flush_msgids_to_ack()
        seqno = self._get_next_odd_seqno()

        await self._flood_sleep()
        message_id = self._mtproto.write(seqno, **pending_request.request)

        self._pending_requests[message_id] = pending_request
        self._loop.call_later(600, self._delete_pending_request, message_id)

        response = await pending_request.response
        self._seqno_increment = 1

        if message_id in self._pending_requests:
            del self._pending_requests[message_id]

        return response

    async def mtproto_loop(self):
        while True:
            self._mtproto_read_future = self._loop.create_task(self._mtproto.read())
            message_mtproto = await self._mtproto_read_future
            self._process_telegram_message(message_mtproto)

            if len(self._msgids_to_ack) >= 32 or (time.time() - self._last_time_acks_flushed) > 10:
                self._flush_msgids_to_ack()

    def _process_telegram_message(self, message) -> None:
        self._update_last_seqno_from_incoming_message(message)

        body = message.body.packed_data if message.body == "gzip_packed" else message.body

        if body == "msg_container":
            for m in body.messages:
                self._process_telegram_message(m)

        else:
            self._process_telegram_message_body(body)
            self._acknowledge_telegram_message(message)

    def _process_telegram_message_body(self, body):
        if body == "new_session_created":
            pass

        elif body == "msgs_ack":
            pass

        elif body == "bad_server_salt":
            self._process_bad_server_salt(body)

        elif body == "bad_msg_notification" and body.error_code == 32 and not self._stable_seqno:
            # msg_seqno too low
            self._process_bad_msg_notification_msg_seqno_too_low(body)

        elif body == "rpc_result":
            if body.result == "rpc_error" and body.result.error_message[:11] == "FLOOD_WAIT_":
                self._process_rpc_error_flood_wait(body)
            else:
                self._process_rpc_result(body)

    def _acknowledge_telegram_message(self, message):
        if message.seqno % 2 == 1:
            self._msgids_to_ack.append(message.msg_id)
            self._flush_msgids_to_ack()

    def _flush_msgids_to_ack(self):
        self._last_time_acks_flushed = time.time()

        if not self._msgids_to_ack or not self._stable_seqno:
            return

        seqno = self._get_next_even_seqno()
        self._mtproto.write(seqno, _cons="msgs_ack", msg_ids=self._msgids_to_ack)
        self._msgids_to_ack = []

    def _update_last_seqno_from_incoming_message(self, message):
        self._last_seqno = max(self._last_seqno, message.seqno)

    def _process_bad_server_salt(self, body):
        if self._mtproto.get_server_salt != 0:
            self._stable_seqno = False

        self._mtproto.set_server_salt(body.new_server_salt)
        logging.log(logging.DEBUG, f"updating salt: {body.new_server_salt:d}")

        if body.bad_msg_id in self._pending_requests:
            bad_request = self._pending_requests[body.bad_msg_id]
            self._loop.create_task(self._rpc_call(bad_request))

        else:
            logging.log(logging.DEBUG, "bad_msg_id not found")

    def _process_bad_msg_notification_msg_seqno_too_low(self, body):
        self._seqno_increment = min(2 ** 31 - 1, self._seqno_increment << 1)
        self._last_seqno += self._seqno_increment

        logging.log(logging.DEBUG, f"updating seqno by {self._seqno_increment:d} to {self._last_seqno:d}")

        if body.bad_msg_id in self._pending_requests:
            bad_request = self._pending_requests[body.bad_msg_id]
            self._loop.create_task(self._rpc_call(bad_request))
            del self._pending_requests[body.bad_msg_id]

    def _process_rpc_error_flood_wait(self, body):
        seconds_to_wait = 2 * int(body.result.error_message[11:])
        self._set_flood_wait(seconds_to_wait)

        if body.req_msg_id in self._pending_requests:
            pending_request = self._pending_requests[body.req_msg_id]
            self._loop.create_task(self._rpc_call(pending_request))
            del self._pending_requests[body.bad_msg_id]

    def _process_rpc_result(self, body):
        self._stable_seqno = True

        if body.req_msg_id in self._pending_requests:
            pending_request = self._pending_requests[body.req_msg_id]

            if body.result == "gzip_packed":
                result = body.result.packed_data
            else:
                result = body.result

            pending_request.response.set_result(result.get_dict())

    def _flood_wait(self):
        return self._future_flood_wait is not None and not self._future_flood_wait.done()

    async def _flood_sleep(self):
        if self._flood_wait():
            await self._future_flood_wait

    def _set_flood_wait(self, seconds_to_wait):
        if not self._flood_wait():
            self._future_flood_wait = self._loop.create_future()
            self._loop.create_task(self._resume_after_flood_wait_delay(seconds_to_wait))

    async def _resume_after_flood_wait_delay(self, seconds_to_wait):
        logging.log(logging.DEBUG, "FLOOD_WAIT for %d seconds", seconds_to_wait)
        await asyncio.sleep(seconds_to_wait)
        self._future_flood_wait.set_result(True)

    def disconnect(self):
        self._mtproto_read_future.cancel()
        self._flush_msgids_to_ack()
        self._loop.create_task(self._mtproto.stop())
        self._mtproto = None

    def get_session(self) -> tuple[str, int]:
        if self._mtproto is None:
            raise ConnectionError("Session not connected")

        return self._mtproto.get_session()

    def set_session(self, session: tuple[str, int] | None):
        if self._mtproto is not None:
            raise ConnectionError("Session already connected")

        self._session = session
