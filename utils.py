"""
Convenience utils for use in avs and parsers
"""

from datetime import datetime, timezone
from enum import Enum


class OperatingSystem(Enum):
    WINDOWS = "windows"
    UNIX = "unix"
    LINUX = "linux"


class RawTimeConverter:
    def __init__(self, time_type: str):
        self.time_type = OperatingSystem(time_type)

    def _decode_windows(self, wintime_bytes: bytes) -> datetime:
        wintime = int.from_bytes(wintime_bytes, byteorder="little")
        magic_number = 11644473600
        timestamp = (wintime // 10000000) - magic_number
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)

    def _decode_unix(self, unixtime_bytes: bytes) -> datetime:
        timestamp = int.from_bytes(unixtime_bytes, byteorder="little")
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)

    def decode(self, time_bytes: bytes) -> datetime:
        if self.time_type == OperatingSystem.WINDOWS:
            return self._decode_windows(time_bytes)

        if self.time_type == OperatingSystem.UNIX:
            return self._decode_unix(time_bytes)

        raise NotImplementedError
