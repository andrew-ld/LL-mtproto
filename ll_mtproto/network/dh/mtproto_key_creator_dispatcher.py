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

from ll_mtproto.crypto.auth_key import DhGenKey
from ll_mtproto.crypto.providers.crypto_provider_base import CryptoProviderBase
from ll_mtproto.network.datacenter_info import DatacenterInfo
from ll_mtproto.network.dh.mtproto_key_creator import MTProtoKeyCreator
from ll_mtproto.network.dispatcher import Dispatcher
from ll_mtproto.network.mtproto import MTProto
from ll_mtproto.tl.structure import Structure
from ll_mtproto.typed import InThread

__all__ = ("initialize_key_creator_dispatcher", "KeyCreatorDispatcher")


class KeyCreatorDispatcher(Dispatcher):
    __slots__ = ("_creator", "_mtproto")

    _creator: MTProtoKeyCreator
    _mtproto: MTProto

    def __init__(self, creator: MTProtoKeyCreator, mtproto: MTProto):
        self._creator = creator
        self._mtproto = mtproto

    async def process_telegram_message_body(self, body: Structure, crypto_flag: bool) -> None:
        if crypto_flag:
            raise TypeError(f"Expected an plaintext message, found `{body!r}`")

        await self._creator.process_telegram_message_body(body)

    async def process_telegram_signaling_message(self, signaling: Structure, crypto_flag: bool) -> None:
        if crypto_flag:
            raise TypeError(f"Expected an plaintext signaling, found `{signaling!r}`")

        await self._mtproto.write_unencrypted_message(_cons="msgs_ack", msg_ids=[signaling.msg_id])


async def initialize_key_creator_dispatcher(
        temp_key: bool,
        mtproto: MTProto,
        in_thread: InThread,
        datacenter: DatacenterInfo,
        crypto_provider: CryptoProviderBase
) -> tuple[Dispatcher, asyncio.Future[DhGenKey]]:
    result = asyncio.get_running_loop().create_future()
    creator = await MTProtoKeyCreator.initializate(mtproto, in_thread, datacenter, crypto_provider, temp_key, result)
    return KeyCreatorDispatcher(creator, mtproto), result
