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


import cryptg

__all__ = ("factorize", "is_safe_dh_prime")


def factorize(pq: int) -> tuple[int, int]:
    return cryptg.factorize_pq_pair(pq)


def is_safe_dh_prime(g: int, n: int) -> bool:
    match g:
        case 2:
            if n % 8 != 7:
                return False

        case 3:
            if n % 3 != 2:
                return False

        case 4:
            pass

        case 5:
            if n % 5 not in (1, 4):
                return False

        case 6:
            if n % 24 not in (19, 23):
                return False

        case 7:
            if n % 7 not in (3, 5, 6):
                return False

        case _:
            return False

    return True
