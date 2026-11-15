#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
EsetLogParser: Python script for parsing ESET (NOD32) virlog.dat file.
Copyright (C) 2017 Ladislav Baco
Copyright (C) 2025-2026 Jozef Sabo

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import sys

if sys.version_info < (3, 10):
    raise ImportError("eset_virlog_parser requires Python 3.10 or newer")

import argparse
import binascii
import os
import struct
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Generic, TypeVar

__author__ = "Ladislav Baco, Jozef Sabo"
__copyright__ = "Copyright (C) 2017-2026"
__credits__ = "Ladislav Baco, Jozef Sabo"
__license__ = "GPLv3"
__version__ = "0.2.1"
__maintainer__ = "Ladislav Baco"
__status__ = "Development"

TIMEFORMAT = "%Y-%m-%dT%H:%M:%SZ"
RECORD_HEADER = b'\x24\x00\x00\x00\x01\x00\x01\x00'

T = TypeVar('T')


class DataType(Generic[T], ABC):

    @abstractmethod
    def convert(self, data: bytes) -> T:
        pass


class GeneralTimestamp(DataType[datetime], ABC):

    def __init__(self, size: int) -> None:
        self.size = size


class WinTimestamp(GeneralTimestamp):

    def __init__(self) -> None:
        super().__init__(8)

    def convert(self, data: bytes) -> datetime:
        data = data[:self.size]
        if len(data) != self.size:
            raise ValueError("WinTimestamp does not contain enough bytes for size recognition")
        wintime = int.from_bytes(data, byteorder="little")
        magic_number = 11644473600
        timestamp = (wintime // 10000000) - magic_number
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)


class UnixTimestamp(GeneralTimestamp):

    def __init__(self, size: int) -> None:
        super().__init__(size)

    def convert(self, data: bytes) -> datetime:
        data = data[:self.size]
        if len(data) != self.size:
            raise ValueError("UnixTimestamp does not contain enough bytes for size recognition")
        timestamp = int.from_bytes(data, byteorder="little")
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)


class UInt(DataType[int]):

    def __init__(self, size: int) -> None:
        self.size = size

    def convert(self, data: bytes) -> int:
        data = data[:self.size]
        if len(data) != self.size:
            raise ValueError("UInt does not contain enough bytes for size recognition")
        return int.from_bytes(data, byteorder="little")


class WideString(DataType[str]):

    def convert(self, data: bytes) -> str:
        nbytes, data = data[:4], data[4:]
        if len(nbytes) != 4:
            raise ValueError("WideString does not contain enough bytes for size recognition")
        nbytes = int.from_bytes(nbytes, byteorder="little")

        text = data[:nbytes]
        if len(text) != nbytes:
            raise ValueError("WideString does not contain enough data bytes")

        text, null_bytes = text[:-2], text[-2:]
        if null_bytes != b"\x00\x00":
            raise ValueError("WideString does not contain null bytes")

        return text.decode("utf-16-le").strip()


class CString(DataType[str]):

    def convert(self, data: bytes) -> str:
        nbytes, data = data[:4], data[4:]
        if len(nbytes) != 4:
            raise ValueError("CString does not contain enough bytes for size recognition")
        nbytes = int.from_bytes(nbytes, byteorder="little")

        text = data[:nbytes]
        if len(text) != nbytes:
            raise ValueError("CString does not contain enough data bytes")

        text, null_bytes = text[:-1], text[-1:]
        if null_bytes != b"\x00":
            raise ValueError("CString does not contain null byte")

        return text.decode("utf-8").strip()


class Hash(DataType[bytes]):

    def convert(self, data: bytes) -> bytes:
        nbytes, data = data[:4], data[4:]
        if len(nbytes) != 4:
            raise ValueError("Hash does not contain enough bytes for size recognition")
        nbytes = int.from_bytes(nbytes, byteorder="little")

        data = data[:nbytes]
        if len(data) != nbytes:
            raise ValueError("Hash does not contain enough data bytes")
        return data


def _warning_unexpected(field: str) -> None:
    eprint('Warning: unexpected bytes in field ' + field)


def _info_not_found(field: str) -> None:
    eprint('Info: field not found: ' + field)


def eprint(*args: Any, **kwargs: Any) -> None:
    """Prints debug messages to stderr."""
    print(*args, file=sys.stderr, **kwargs)


class EsetVirlogParser:
    INTERESTING_DATA_HEADERS = {
        "program_hash": (bytes([0x9d, 0x13, 0x42, 0x00]), Hash()),
        "object_hash": (bytes([0x9e, 0x13, 0x42, 0x00]), Hash()),
        "object_hash3": (bytes([0xa4, 0x13, 0x42, 0x00]), Hash()),
        "object_hash2": (bytes([0xae, 0x13, 0x42, 0x00]), Hash()),
        "win_signing_cert_pubkey_fingerprint_hash": (bytes([0xb3, 0x13, 0x42, 0x00]), Hash()),
        "win_signing_cert_pubkey_params": (bytes([0xb2, 0x13, 0x45, 0x00]), UInt(4)),
        "win_lang_id": (bytes([0x87, 0x27, 0x45, 0x00]), UInt(4)),
        "firstseen": (bytes([0x9f, 0x13, 0x46, 0x00]), UnixTimestamp(8)),
        "source_web": (bytes([0x92, 0x27, 0x4d, 0x00]), CString()),
        "user_name": (bytes([0xee, 0x03, 0x4e, 0x00]), WideString()),
        "win_user_sid": (bytes([0xf5, 0x03, 0x4e, 0x00]), WideString()),
        "object_name": (bytes([0xbe, 0x0b, 0x4e, 0x00]), WideString()),
        "program_name": (bytes([0xc4, 0x0b, 0x4e, 0x00]), WideString()),
        "progpath_name": (bytes([0xa7, 0x13, 0x4e, 0x00]), WideString()),
        "path_name": (bytes([0xa9, 0x13, 0x4e, 0x00]), WideString()),
        "win_signing_cert": (bytes([0xb4, 0x13, 0x4e, 0x00]), WideString()),
        "execution_mode": (bytes([0x59, 0x1b, 0x4e, 0x00]), WideString()),
        "infiltration_name": (bytes([0x4d, 0x1d, 0x4e, 0x00]), WideString()),
        "virus_db": (bytes([0x17, 0x27, 0x4e, 0x00]), WideString()),
        "win_company_name": (bytes([0x88, 0x27, 0x4e, 0x00]), WideString()),
        "win_product_name3": (bytes([0x89, 0x27, 0x4e, 0x00]), WideString()),
        "win_file_version": (bytes([0x8a, 0x27, 0x4e, 0x00]), WideString()),
        "win_product_name2": (bytes([0x8b, 0x27, 0x4e, 0x00]), WideString()),
        "win_legal_copyright": (bytes([0x8c, 0x27, 0x4e, 0x00]), WideString()),
        "win_exe_name": (bytes([0x8d, 0x27, 0x4e, 0x00]), WideString()),
        "win_product_name": (bytes([0x8e, 0x27, 0x4e, 0x00]), WideString()),
        "win_product_version": (bytes([0x8f, 0x27, 0x4e, 0x00]), WideString()),
    }

    _BASE_OUTPUT_FIELDS: tuple[str, ...] = (
        "timestamp",
        "virus_db",
        "object_name",
        "object_hash",
        "infiltration_name",
        "user_name",
        "program_name",
        "program_hash",
        "firstseen",
    )
    OUTPUT_FIELDS = tuple(dict.fromkeys(_BASE_OUTPUT_FIELDS + tuple(INTERESTING_DATA_HEADERS)))

    @staticmethod
    def _check_id(record_id: int, raw_record: bytes) -> None:
        little_endian_ids = [raw_record[0:4], raw_record[16:20]]
        for little_endian_id in little_endian_ids:
            if struct.unpack('<L', little_endian_id)[0] != record_id:
                _warning_unexpected('ID')

    @classmethod
    def get_raw_records(cls, raw_data: bytes) -> list[tuple[int, bytes]]:
        raw_records = raw_data.split(RECORD_HEADER)[1:]
        zip_records = zip(range(len(raw_records)), raw_records, strict=True)
        records = []
        for record_id, raw_record in zip_records:
            cls._check_id(record_id, raw_record)
            records.append((record_id, raw_record))
        return records

    @staticmethod
    def _extract_data_type(data_type: str, record: dict[str, Any]) -> str:
        data = record.get(data_type, None)

        if data is None:
            _info_not_found(data_type)
            return ''

        match data:
            case bytes():
                return binascii.hexlify(data).decode('utf-8')
            case datetime():
                return data.strftime(TIMEFORMAT)
            case _:
                return str(data)

    @classmethod
    def extract_data_from_record(cls, data: bytes) -> dict[str, Any]:
        record_data = {}
        try:
            record_data["timestamp"] = WinTimestamp().convert(data[4:])
        except Exception:
            print("Error. Cannot parse timestamp.")

        for header_name, (header, data_type) in cls.INTERESTING_DATA_HEADERS.items():
            idx = data.find(header)
            if idx == -1:
                continue
            idx += 4
            try:
                res = data_type.convert(data[idx:])
            except Exception as e:
                eprint(
                    "Error when parsing record. Data for \"{}\" of type {} on position {}: {}".format(
                        header_name, data_type.__class__.__name__, idx - 4, e
                    )
                )
            else:
                record_data[header_name] = res

        return record_data

    @classmethod
    def parse_record(cls, record_id: int, record: dict[str, Any]) -> list[str]:
        parsed_record = [str(record_id), cls._extract_data_type("firstseen", record)]
        parsed_record.extend(cls._extract_data_type(field, record) for field in cls.OUTPUT_FIELDS[1:])
        return parsed_record

    def parse_records(self, virlog_data: bytes) -> list[list[str]]:
        parsed_records = [['ID'] + list(self.OUTPUT_FIELDS)]
        for idx, record in self.get_raw_records(virlog_data):
            parsed_records.append(self.parse_record(idx, self.extract_data_from_record(record)))
        return parsed_records


def _parse_args(args: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='EsetLogParser: Python script for parsing ESET (NOD32) virlog.dat file.')
    parser.add_argument('virlog', help='path to virlog.dat file')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + __version__)
    return parser.parse_args(args)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    if not os.path.isfile(args.virlog):
        raise Exception('Virlog file does not exist')

    with open(args.virlog, 'rb') as f:
        virlog_data = f.read()

    parser = EsetVirlogParser()
    parsed_records = parser.parse_records(virlog_data)
    print('\n'.join(';'.join(record) for record in parsed_records))


if __name__ == "__main__":
    main()
