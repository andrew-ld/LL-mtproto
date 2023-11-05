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


__all__ = ("Dispatcher", "dispatch_event")

import logging
import abc

from . import MTProto
from ..crypto import DhGenKey, Key
from ..tl import TlMessageBody, Structure


class Dispatcher(abc.ABC):
    @abc.abstractmethod
    async def process_telegram_message_body(self, body: Structure, crypto_flag: bool):
        raise NotImplementedError

    @abc.abstractmethod
    async def process_telegram_signaling_message(self, signaling: Structure, crypto_flag: bool):
        raise NotImplementedError


async def _process_telegram_message(dispatcher: Dispatcher, signaling: Structure, body: Structure, crypto_flag: bool):
    await dispatcher.process_telegram_signaling_message(signaling, crypto_flag)

    if body == "msg_container":
        for m in body.messages:
            await _process_telegram_message(dispatcher, m, m.body, crypto_flag)

    else:
        await dispatcher.process_telegram_message_body(body, crypto_flag)


async def _process_inbound_message(dispatcher: Dispatcher, signaling: TlMessageBody, body: TlMessageBody, crypto_flag: bool):
    logging.debug("received message (%s) %d from mtproto", body.constructor_name, signaling.msg_id)
    await _process_telegram_message(dispatcher, signaling, body, crypto_flag)


async def dispatch_event(dispatcher: Dispatcher, mtproto: MTProto, encryption_key: Key | DhGenKey | None):
    crypto_flag = encryption_key is not None

    if crypto_flag:
        signaling, body = await mtproto.read_encrypted(encryption_key)
    else:
        signaling, body = await mtproto.read_unencrypted_message()

    await _process_inbound_message(dispatcher, signaling, body, crypto_flag)
