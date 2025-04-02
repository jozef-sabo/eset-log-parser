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

from datetime import datetime
import argparse
import os
import sys

from eset_virlog_parser import EsetVirlogParser

TIMEFORMAT = "%Y-%m-%dT%H:%M:%SZ"


def eprint(*args, **kwargs):
    """Prints debug messages to stderr"""
    print(*args, file=sys.stderr, **kwargs)


def _infoNotFound(field):
    eprint("Info: field not found: " + field)


def _warningUnexpected(field):
    eprint("Warning: unexpected bytes in field " + field)


def convertToDict(parser: EsetVirlogParser):
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


def getRawRecords(virlogParser):
    rawRecords = convertToDict(virlogParser)

    ziprecords = zip(range(len(rawRecords)), rawRecords)
    records = []
    for recordId, rawRecord in ziprecords:
        # create 2D array instead of zip-object in Python 3
        records.append((recordId, rawRecord))
    return records


def processType(field):
    if isinstance(field, EsetVirlogParser.Hash):
        return field.hash.hex()
    if isinstance(field, EsetVirlogParser.Widestr):
        return field.str
    if isinstance(field, EsetVirlogParser.Unixdate):
        return processType(field.date_time)
    if isinstance(field, EsetVirlogParser.Windate):
        return processType(field.date_time)
    if isinstance(field, datetime):
        return field.strftime(TIMEFORMAT)

    return field


def extract_field(record, fieldName):
    field = record.get(fieldName)

    if field is not None:
        return processType(field)

    _infoNotFound(fieldName)
    return "(null)"


def parseRecord(recordId, record: dict):
    timestamp = extract_field(record, "timestamp")
    virusdb = extract_field(record, "virus_db")
    obj = extract_field(record, "object_name")
    objhash = extract_field(record, "object_hash")
    infiltration = extract_field(record, "infiltration_name")
    user = extract_field(record, "user_name")
    if user is not None:
        user = user.split("\\")[1]
    progname = extract_field(record, "program_name")
    proghash = extract_field(record, "program_hash")
    firstseen = extract_field(record, "firstseen")

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


def _parse_args(args):
    parser = argparse.ArgumentParser(
        description="EsetLogParser: Python script for parsing ESET (NOD32) virlog.dat file."
    )
    parser.add_argument("virlog", help="path to virlog.dat file")
    parser.add_argument(
        "-v", "--version", action="version", version="%(prog)s " + __version__
    )
    return parser.parse_args(args)


def main(argv):
    args = _parse_args(argv)

    if not os.path.isfile(args.virlog):
        raise Exception("Virlog file does not exist")

    ep = EsetVirlogParser.from_file(args.virlog)

    rawRecords = getRawRecords(ep)
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
        parsedRecords.append(parseRecord(recordId, rawRecord))
    print("\n".join([";".join(record) for record in parsedRecords]))


if __name__ == "__main__":
    main(sys.argv[1:])
