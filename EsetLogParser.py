#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
EsetLogParser: Python script for parsing ESET (NOD32) virlog.dat file.
Copyright (C) 2017 Ladislav Baco

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from __future__ import print_function

__author__ = "Ladislav Baco"
__copyright__ = "Copyright (C) 2017"
__credits__ = "Ladislav Baco"
__license__ = "GPLv3"
__version__ = "0.2.1"
__maintainer__ = "Ladislav Baco"
__status__ = "Development"

import typing
from datetime import datetime
import argparse
import os
import sys

from eset_ndf_parser import EsetNdfParser
from eset_virlog_parser import EsetVirlogParser

TIMEFORMAT = "%Y-%m-%dT%H:%M:%SZ"


def eprint(*args, **kwargs):
    """Prints debug messages to stderr"""
    print(*args, file=sys.stderr, **kwargs)


def _infoNotFound(field):
    eprint("Info: field not found: " + field)


def _warningUnexpected(field):
    eprint("Warning: unexpected bytes in field " + field)


def convertVirlogToDict(parser: EsetVirlogParser):
    return [
        {
            **{
                y.name.name: y.arg if hasattr(y, "arg") else None
                for y in x.record.data_fields
            },
            "timestamp": x.record.win_timestamp,
        }
        for x in parser.threats
    ]


def convertNDFToDict(parser: EsetNdfParser):
    return {
        "mal_size": parser.mal_size,
        "num_findings": parser.num_findings,
        "mal_hash_sha1": parser.mal_hash_sha1.hex(),
        "datetime": parser.datetime_unix,
        "findings": [
            {
                key: getattr(x, key)
                for key in dir(x)
                if not key.startswith("_")
                and not isinstance(getattr(x, key), typing.Callable)
            }
            for x in parser.findings
        ],
    }


def getRawVirlogRecords(virlogParser):
    rawRecords = convertVirlogToDict(virlogParser)
    return list(enumerate(rawRecords))


def getRawNDFRecords(ndfParser):
    rawRecords = convertNDFToDict(ndfParser)

    records = list(enumerate(rawRecords.pop("findings")))
    header = rawRecords

    return header, records


def processType(field):
    if isinstance(field, EsetVirlogParser.Hash):
        return field.hash.hex()
    if isinstance(field, EsetVirlogParser.Widestr):
        return field.str
    if isinstance(field, EsetVirlogParser.Unixdate):
        return processType(field.date_time)
    if isinstance(field, EsetVirlogParser.Windate):
        return processType(field.date_time)
    if isinstance(field, EsetNdfParser.Widestr):
        return field.str
    if isinstance(field, EsetNdfParser.Unixdate):
        return processType(field.date_time)
    if isinstance(field, EsetNdfParser.Windate):
        return processType(field.date_time)
    if isinstance(field, datetime):
        return field.strftime(TIMEFORMAT)
    if isinstance(field, bytes):
        return field.hex()
    if isinstance(field, int):
        return str(field)

    return field


def extractField(record, fieldName):
    field = record.get(fieldName)

    if field is not None:
        return processType(field)

    _infoNotFound(fieldName)
    return "(null)"


def parseVirlogRecord(recordId, record: dict):
    timestamp = extractField(record, "timestamp")
    virusdb = extractField(record, "virus_db")
    obj = extractField(record, "object_name")
    objhash = extractField(record, "object_hash")
    infiltration = extractField(record, "infiltration_name")
    user = extractField(record, "user_name")
    if user is not None:
        user = user.split("\\")[1]
    progname = extractField(record, "program_name")
    proghash = extractField(record, "program_hash")
    firstseen = extractField(record, "firstseen")

    return [
        str(recordId),
        timestamp,
        virusdb,
        obj,
        objhash,
        infiltration,
        user,
        progname,
        proghash,
        firstseen,
    ]


def parseNdfRecord(recordId, record: dict):
    firstseen = extractField(record, "datetime_first_utc")
    mostRecentSeen = extractField(record, "datetime_latest_occurence")
    quarEncodingStart = extractField(record, "datetime_quar_enc_start")
    quarEncodingFin = extractField(record, "datetime_quar_enc_stop")
    path1 = extractField(record, "mal_path")
    path2 = extractField(record, "mal_path2")
    threat = extractField(record, "threat_canonized")
    threat_local = extractField(record, "threat_local")
    occurrence = extractField(record, "threat_occurence")

    return [
        str(recordId),
        firstseen,
        mostRecentSeen,
        quarEncodingStart,
        quarEncodingFin,
        path1,
        path2,
        threat,
        threat_local,
        occurrence,
    ]


def parseNdfHeader(record: dict):
    maliciousSize = extractField(record, "mal_size")
    numFindings = extractField(record, "num_findings")
    SHA1 = extractField(record, "mal_hash_sha1")
    firstseen = extractField(record, "datetime")

    return [
        firstseen,
        SHA1,
        maliciousSize,
        numFindings,
    ]


def processVirlog(path: str):
    ep = EsetVirlogParser.from_file(path)

    rawRecords = getRawVirlogRecords(ep)
    parsedRecords = [
        [
            "ID",
            "Timestamp",
            "VirusDB",
            "Object",
            "ObjectHash",
            "Infiltration",
            "User",
            "ProgName",
            "ProgHash",
            "FirstSeen",
        ]
    ]
    for recordId, rawRecord in rawRecords:
        parsedRecords.append(parseVirlogRecord(recordId, rawRecord))
    print("\n".join([";".join(record) for record in parsedRecords]))


def processNDF(path: str):
    ep = EsetNdfParser.from_file(path)

    header, rawRecords = getRawNDFRecords(ep)

    parsedHeader = [
        [
            "FirstSeen",
            "HexSHA1",
            "MaliciousFileSize",
            "NumberOfFindings",
        ],
        parseNdfHeader(header),
    ]
    print("\n".join([";".join(record) for record in parsedHeader]))

    parsedRecords = [
        [
            "ID",
            "FirstSeen",
            "MostRecentSeen",
            "QuarantineEncodingStart",
            "QuarantineEncodingFinished",
            "Path1",
            "Path2",
            "Infiltration",
            "InfiltrationLocalized",
            "NumberOfDetections",
        ]
    ]
    for recordId, rawRecord in rawRecords:
        parsedRecords.append(parseNdfRecord(recordId, rawRecord))
    print("\n".join([";".join(record) for record in parsedRecords]))


def processFile(filetype: str, path: str):
    if filetype == "virlog":
        return processVirlog(path)

    if filetype == "ndf":
        return processNDF(path)

    assert False


def _parse_args(args):
    parser = argparse.ArgumentParser(
        description="EsetLogParser: Python script for parsing ESET (NOD32) virlog.dat and quarantine metadata .ndf files."
    )
    parser.add_argument("path", help="path to virlog.dat or .ndf file")
    parser.add_argument(
        "-v", "--version", action="version", version="%(prog)s " + __version__
    )
    parser.add_argument("-t", "--type", choices=["virlog", "ndf"], default="virlog")
    return parser.parse_args(args)


def main(argv):
    args = _parse_args(argv)

    if not os.path.isfile(args.path):
        raise Exception(f"{args.type} file does not exist")

    processFile(args.type, args.path)


if __name__ == "__main__":
    main(sys.argv[1:])
