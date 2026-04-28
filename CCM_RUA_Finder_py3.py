#!/usr/bin/env python3

#
# CCM_RUA_Finder.py
# Version 1.2 #StatusUpdate - Python 3 port
# Thanks to Chakib (@Tecko921) for the status update feature request, testing, and feedback!
#
# Original Author:
# David Pany - Mandiant (FireEye) - 2017
# Twitter: @DavidPany
#
# Editor:
# Fred House - Mandiant (FireEye) - 2016
# Twitter: @0xF2EDCA5A
#
# Python 3 port notes:
# - Removed `from __future__ import print_function` (built-in in Python 3)
# - All string literals used as byte patterns changed to bytes literals (b"...")
# - File opened in binary mode; regex patterns compiled as bytes patterns (rb"...")
# - `data_blocks` stores bytes objects; comparisons use bytes literals
# - `current_buffer < SEEK_REWIND_SIZE` corrected to `current_seek < SEEK_REWIND_SIZE`
# - `struct.unpack` calls unchanged (already work on bytes)
# - stdout status writes use sys.stdout.write (unchanged)
# - logging.warn -> logging.warning (deprecated in Python 3)
# - sanitize_string now operates on str decoded from bytes where needed
#
# Usage:
# CCM_RUA_Finder_py3.py -i path/to/OBJECTS.DATA -o path/to/output.tsv
#

import os
import re
import struct
import argparse
from datetime import datetime, timedelta
import logging
import sys

# Set up logging - default level WARN
logging.basicConfig(level=logging.WARNING)

# WMI GUIDs for CCM RUA class instances (bytes, for binary file matching)
CCM_RUA_GUID_VISTA_UTF16 = (
    "7C261551B264D35E30A7FA29C75283DAE04BBA71DBE8F5E553F7AD381B406DD8"
    .encode('utf-16le'))

CCM_RUA_GUID_XP_UTF16 = ("6FA62F462BEF740F820D72D9250D743C"
                          .encode('utf-16le'))

# Constants
SEEK_REWIND_SIZE = 300
DEFAULT_READ_SIZE = 50
BLOCK_READ_SIZE = 2100
MATCH_PARTIAL_FAST_FORWARD = 31
MISS_PARTIAL_REWIND = 19


def update_status(current_progress, full_progress):
    """Manage command line status updates."""
    sys.stdout.write("\b" * 40)
    sys.stdout.write("{}".format(" " * 50))
    sys.stdout.write("\b" * 50)
    sys.stdout.flush()
    sys.stdout.write("\t\t{}% complete...".format(
        ((current_progress * 100) // full_progress)))
    sys.stdout.flush()


def find_ccm_rua_data(od_path):
    """Return 2100-byte chunks of data that contain CCM_RUA entries."""
    max_seek_size = os.path.getsize(od_path)
    od_file = open(od_path, "rb")
    current_seek = 0
    data_blocks = set()

    logging.info("Reading File")
    loop_count = 0

    # Search needle as bytes
    needle = b"CCM_RecentlyUsedApps"

    while current_seek <= max_seek_size:
        if loop_count % 1000000 == 0:
            update_status(current_seek, max_seek_size)

        current_buffer = od_file.read(DEFAULT_READ_SIZE)
        current_seek += DEFAULT_READ_SIZE

        if needle in current_buffer:
            old_seek = current_seek

            # Rewind to capture full header
            if current_seek < SEEK_REWIND_SIZE:  # Bug fix: was comparing buffer object
                current_seek = 0
            else:
                current_seek = current_seek - SEEK_REWIND_SIZE

            od_file.seek(current_seek)
            rua_buffer = od_file.read(BLOCK_READ_SIZE)
            data_blocks.add(rua_buffer)

            current_seek = old_seek + MATCH_PARTIAL_FAST_FORWARD
        else:
            old_seek = current_seek
            current_seek = old_seek - MISS_PARTIAL_REWIND
            od_file.seek(current_seek)

        loop_count += 1

    update_status(max_seek_size, max_seek_size)
    logging.info("Completed Reading File")
    od_file.close()
    return data_blocks


def main():
    """Search all data chunks containing CCM RUA data and parse them."""
    parser = argparse.ArgumentParser(
        description='Parse WMI repository OBJECTS.DATA for CCM_RecentlyUsedApps records.')
    parser.add_argument('-i', '--input', help='path to an OBJECTS.DATA file', required=True)
    parser.add_argument('-o', '--output', help='path to tab delimited output file')
    args = parser.parse_args()

    all_ccm_data_set = find_ccm_rua_data(args.input)

    if args.output:
        output_file = open(args.output, "w", encoding="utf-8")
    else:
        output_file = None

    # XML regex (bytes pattern)
    ccm_xml_mo = re.compile(
        rb"<CCM_RecentlyUsedApps><AdditionalProductCodes>"
        rb"(?P<additional_product_codes>.*?)</AdditionalProductCodes>"
        rb"<CompanyName>(?P<company_name>.*?)</CompanyName><ExplorerFileName>"
        rb"(?P<explorer_file_name>.*?)</ExplorerFileName><FileDescription>"
        rb"(?P<file_description>.*?)</FileDescription><FilePropertiesHash>"
        rb"(?P<file_properties_hash>.*?)</FilePropertiesHash><FileSize>"
        rb"(?P<file_size>.*?)</FileSize><FileVersion>(?P<file_version>.*?)"
        rb"</FileVersion><FolderPath>(?P<folder_path>.*?)</FolderPath>"
        rb"<LastUsedTime>(?P<last_used_time>.*?)</LastUsedTime><LastUserName>"
        rb"(?P<last_user_name>.*?)</LastUserName><msiDisplayName>"
        rb"(?P<msi_display_name>.*?)</msiDisplayName><msiPublisher>"
        rb"(?P<msi_publisher>.*?)</msiPublisher><msiVersion>"
        rb"(?P<msi_version>.*?)</msiVersion><OriginalFileName>"
        rb"(?P<original_file_name>.*?)</OriginalFileName><ProductCode>"
        rb"(?P<product_code>.*?)</ProductCode><ProductLanguage>"
        rb"(?P<product_language>.*?)</ProductLanguage><ProductName>"
        rb"(?P<product_name>.*?)</ProductName><ProductVersion>"
        rb"(?P<product_version>.*?)</ProductVersion><SoftwarePropertiesHash>"
        rb"(?P<software_properties_hash>.*?)</SoftwarePropertiesHash>"
        rb"</CCM_RecentlyUsedApps>")

    # Null-delimited carved (bytes pattern)
    ccm_nulldel_carve_mo = re.compile(
        rb"CCM_RecentlyUsedApps\x00\x00"
        rb"(?P<additional_product_codes>[^\x00]*)\x00\x00"
        rb"(?P<company_name>[^\x00]*)\x00\x00"
        rb"(?P<explorer_file_name>[^\x00]*)\x00\x00"
        rb"(?P<file_description>[^\x00]*)\x00\x00"
        rb"(?P<file_properties_hash>[^\x00]*)\x00\x00"
        rb"(?P<file_version>[^\x00]*)\x00\x00"
        rb"(?P<folder_path>[^\x00]*)\x00\x00"
        rb"(?P<last_used_time>[^\x00]*)\x00\x00"
        rb"(?P<last_user_name>[^\x00]*)\x00\x00"
        rb"(?P<msi_display_name>[^\x00]*)\x00\x00"
        rb"(?P<msi_publisher>[^\x00]*)\x00\x00"
        rb"(?P<msi_version>[^\x00]*)\x00\x00"
        rb"(?P<original_file_name>[^\x00]*)\x00\x00"
        rb"(?P<product_language>[^\x00]*)\x00\x00"
        rb"(?P<product_name>[^\x00]*)\x00\x00"
        rb"(?P<product_version>[^\x00]*)\x00\x00"
        rb"(?P<software_properties_hash>[^\x00]*)")

    # Null-delimited full (with GUID header) — bytes pattern
    guid_pattern = (re.escape(CCM_RUA_GUID_VISTA_UTF16)
                    + b"|" + re.escape(CCM_RUA_GUID_XP_UTF16))
    ccm_nulldel_full_mo = re.compile(
        rb"(?P<GUID>" + guid_pattern + rb")"
        rb"(?P<rua_header>[\x00-\xFF]{20,250}?)CCM_RecentlyUsedApps\x00\x00"
        rb"(?P<additional_product_codes>[^\x00]*)\x00\x00"
        rb"(?P<company_name>[^\x00]*)\x00\x00"
        rb"(?P<explorer_file_name>[^\x00]*)\x00\x00"
        rb"(?P<file_description>[^\x00]*)\x00\x00"
        rb"(?P<file_properties_hash>[^\x00]*)\x00\x00"
        rb"(?P<file_version>[^\x00]*)\x00\x00"
        rb"(?P<folder_path>[^\x00]*)\x00\x00"
        rb"(?P<last_used_time>[^\x00]*)\x00\x00"
        rb"(?P<last_user_name>[^\x00]*)\x00\x00"
        rb"(?P<msi_display_name>[^\x00]*)\x00\x00"
        rb"(?P<msi_publisher>[^\x00]*)\x00\x00"
        rb"(?P<msi_version>[^\x00]*)\x00\x00"
        rb"(?P<original_file_name>[^\x00]*)\x00\x00"
        rb"(?P<product_language>[^\x00]*)\x00\x00"
        rb"(?P<product_name>[^\x00]*)\x00\x00"
        rb"(?P<product_version>[^\x00]*)\x00\x00"
        rb"(?P<software_properties_hash>[^\x00]*)")

    header_string = ('"Format"\t"FolderPath"\t"ExplorerFileName"\t"FileSize"\t'
                     '"LastUserName"\t"LastUsedTime"\t"TimeZoneOffset"\t"LaunchCount"\t'
                     '"Timestamp1"\t"Timestamp2"\t"OriginalFileName"\t"FileDescription"\t'
                     '"CompanyName"\t"ProductName"\t"ProductVersion"\t"FileVersion"\t'
                     '"AdditionalProductCodes"\t"msiVersion"\t"msiDisplayName"\t'
                     '"SoftwarePropertiesHash"\t"ProductCode"\t"ProductLanguage"\t'
                     '"msiPublisher"\t"FilePropertiesHash"')

    if output_file:
        output_file.write("{}\n".format(header_string))
    else:
        print(header_string)

    for ccm_data in all_ccm_data_set:
        ccm_nulldel_full_match = re.search(ccm_nulldel_full_mo, ccm_data)
        ccm_nulldel_carve_match = re.search(ccm_nulldel_carve_mo, ccm_data)
        ccm_xml_match = re.search(ccm_xml_mo, ccm_data)

        if ccm_nulldel_full_match:
            parse_null_delimited_record(ccm_nulldel_full_match, True, output_file)
        elif ccm_nulldel_carve_match:
            parse_null_delimited_record(ccm_nulldel_carve_match, False, output_file)
        elif ccm_xml_match:
            parse_xml_record(ccm_xml_match, output_file)
        else:
            # Ignore known non-record instances of the CCM RUA tag
            ignored_needles = [
                b"CCM_RecentlyUsedApps\x00\x00AdditionalProductCode",
                b"CCM_RecentlyUsedApps\x00\x00\\\\.\\root\\",
                b"CCM_RecentlyUsedApps\x00\x00AAInstProv",
                b"class CCM_RecentlyUsedApps",
                b"instance of InventoryDataItem",
                b"</CCM_RecentlyUsedApps>",
                b'"CCM_RecentlyUsedApps"',
            ]
            if any(n in ccm_data for n in ignored_needles):
                pass
            elif (b"CCM_RecentlyUsedApps>" in ccm_data
                  and b"</CCM_RecentlyUsedApps>" not in ccm_data):
                pass
            else:
                logging.warning("Potentially missed line:\n")
                logging.warning("{}\n\n".format(ccm_data).replace("\\x00", " "))

    if output_file:
        output_file.close()


def _decode(b):
    """Decode bytes to str, ignoring undecodable bytes."""
    if isinstance(b, bytes):
        return b.decode('utf-8', errors='replace')
    return b if b is not None else ""


def parse_null_delimited_record(ccm_nulldel_match, full_tf, output_file):
    """Parse records delimited by \\x00\\x00."""
    timestamps_exist = False
    timestamp_1 = timestamp_2 = file_size = launch_count = " "

    if full_tf:
        header_data = (ccm_nulldel_match.group("GUID")
                       + ccm_nulldel_match.group("rua_header"))

        if CCM_RUA_GUID_VISTA_UTF16 in header_data or CCM_RUA_GUID_XP_UTF16 in header_data:
            record_type = ("Vista+_Full_NullDelim"
                           if CCM_RUA_GUID_VISTA_UTF16 in header_data
                           else "XP_Full_NullDelim")

            guid_pattern_hd = (re.escape(CCM_RUA_GUID_VISTA_UTF16)
                                + b"|" + re.escape(CCM_RUA_GUID_XP_UTF16))
            header_data_mo = re.compile(
                rb"(?P<GUID>" + guid_pattern_hd + rb")"
                rb"(?P<timestamp_1>[\x00-\xFF]{8})(?P<timestamp_2>[\x00-\xFF]{8})"
                rb"(?P<unused>[\x00-\xFF]{34})(?P<file_size>[\x00-\xFF]{4})"
                rb"(?P<unused2>[\x00-\xFF]{20})(?P<launch_count>[\x00-\xFF]{4})")

            header_data_match = re.search(header_data_mo, header_data)
            if header_data_match:
                ts1_bin = header_data_match.group("timestamp_1")
                ts2_bin = header_data_match.group("timestamp_2")
                ts1_nano = struct.unpack("<Q", ts1_bin)[0]
                ts2_nano = struct.unpack("<Q", ts2_bin)[0]
                timestamp_1 = convert_nano_to_human_time(ts1_nano)
                timestamp_2 = convert_nano_to_human_time(ts2_nano)
                file_size = struct.unpack("<L", header_data_match.group("file_size"))[0]
                launch_count = struct.unpack("<L", header_data_match.group("launch_count"))[0]
                timestamps_exist = True

        if not timestamps_exist:
            record_type = "Carved_NullDelim"
    else:
        record_type = "Carved_NullDelim"

    additional_product_codes = _decode(ccm_nulldel_match.group("additional_product_codes"))
    company_name             = _decode(ccm_nulldel_match.group("company_name"))
    explorer_file_name       = _decode(ccm_nulldel_match.group("explorer_file_name"))
    file_description         = _decode(ccm_nulldel_match.group("file_description"))
    file_properties_hash     = _decode(ccm_nulldel_match.group("file_properties_hash"))
    file_version             = _decode(ccm_nulldel_match.group("file_version"))
    folder_path              = _decode(ccm_nulldel_match.group("folder_path"))
    raw_time                 = _decode(ccm_nulldel_match.group("last_used_time"))
    last_user_name           = _decode(ccm_nulldel_match.group("last_user_name"))
    msi_display_name         = _decode(ccm_nulldel_match.group("msi_display_name"))
    msi_publisher            = _decode(ccm_nulldel_match.group("msi_publisher"))
    msi_version              = _decode(ccm_nulldel_match.group("msi_version"))
    original_file_name       = _decode(ccm_nulldel_match.group("original_file_name"))
    product_language         = _decode(ccm_nulldel_match.group("product_language"))
    product_name             = _decode(ccm_nulldel_match.group("product_name"))
    product_version          = _decode(ccm_nulldel_match.group("product_version"))
    software_properties_hash = _decode(ccm_nulldel_match.group("software_properties_hash"))

    year, month, day = raw_time[:4], raw_time[4:6], raw_time[6:8]
    hour, minute, second = raw_time[8:10], raw_time[10:12], raw_time[12:14]
    last_used_time = "{}-{}-{} {}:{}:{}".format(year, month, day, hour, minute, second)
    time_zone_offset = raw_time[-4:]

    product_code = " "

    raw_print_string = (
        '{}\t"{}"\t"{}"\t"{}"\t"{}"\t"{}"'
        '\t="{}"\t"{}"\t"{}"\t"{}"\t"{}"\t"{}"\t"{}"\t"{}"\t"{}"'
        '\t"{}"\t"{}"\t"{}"\t"{}"\t"{}"\t"{}"\t"{}"\t"{}"\t"{}"').format(
        record_type, folder_path, explorer_file_name, file_size, last_user_name,
        last_used_time, time_zone_offset, launch_count, timestamp_1,
        timestamp_2, original_file_name, file_description, company_name,
        product_name, product_version, file_version,
        additional_product_codes, msi_version, msi_display_name,
        software_properties_hash, product_code, product_language,
        msi_publisher, file_properties_hash)

    if output_file:
        output_file.write("{}\n".format(sanitize_string(raw_print_string)))
    else:
        print(sanitize_string(raw_print_string))


def parse_xml_record(ccm_xml_match, output_file):
    """Parse XML formatted records."""
    additional_product_codes = _decode(ccm_xml_match.group("additional_product_codes"))
    company_name             = _decode(ccm_xml_match.group("company_name"))
    explorer_file_name       = _decode(ccm_xml_match.group("explorer_file_name"))
    file_description         = _decode(ccm_xml_match.group("file_description"))
    file_properties_hash     = _decode(ccm_xml_match.group("file_properties_hash"))
    file_size                = _decode(ccm_xml_match.group("file_size"))
    file_version             = _decode(ccm_xml_match.group("file_version"))
    folder_path              = _decode(ccm_xml_match.group("folder_path")).replace("\\\\", "\\")
    raw_time                 = _decode(ccm_xml_match.group("last_used_time"))
    last_user_name           = _decode(ccm_xml_match.group("last_user_name")).replace("\\\\", "\\")
    msi_display_name         = _decode(ccm_xml_match.group("msi_display_name"))
    msi_publisher            = _decode(ccm_xml_match.group("msi_publisher"))
    msi_version              = _decode(ccm_xml_match.group("msi_version"))
    original_file_name       = _decode(ccm_xml_match.group("original_file_name"))
    product_code             = _decode(ccm_xml_match.group("product_code"))
    product_language         = _decode(ccm_xml_match.group("product_language"))
    product_name             = _decode(ccm_xml_match.group("product_name"))
    product_version          = _decode(ccm_xml_match.group("product_version"))
    software_properties_hash = _decode(ccm_xml_match.group("software_properties_hash"))

    year, month, day = raw_time[:4], raw_time[4:6], raw_time[6:8]
    hour, minute, second = raw_time[8:10], raw_time[10:12], raw_time[12:14]
    last_used_time = "{}-{}-{} {}:{}:{}".format(year, month, day, hour, minute, second)
    time_zone_offset = raw_time[-4:]

    timestamp_1 = timestamp_2 = launch_count = ""

    raw_print_string = (
        '"XML"\t"{}"\t"{}"\t"{}"\t"{}"\t"{}"\t="{}"\t"{}"\t"{}"\t"{}"\t'
        '"{}"\t"{}"\t"{}"\t"{}"\t"{}"\t"{}"\t"{}"\t"{}"\t"{}"\t"{}"\t'
        '"{}"\t"{}"\t"{}"\t"{}"').format(
        folder_path, explorer_file_name, file_size, last_user_name,
        last_used_time, time_zone_offset, launch_count, timestamp_1,
        timestamp_2, original_file_name, file_description, company_name,
        product_name, product_version, file_version,
        additional_product_codes, msi_version, msi_display_name,
        software_properties_hash, product_code, product_language,
        msi_publisher, file_properties_hash)

    if output_file:
        output_file.write("{}\n".format(sanitize_string(raw_print_string)))
    else:
        print("{}\n".format(sanitize_string(raw_print_string)))


def sanitize_string(input_string):
    """Remove non-friendly characters from output strings."""
    return (input_string.replace("\\\\x0020", " ")
            .replace("\\\\\\\\", "\\").replace("\\x0020", " ")
            .replace("\\\\", "\\").replace("&#174;", "(R)")
            .replace("\\x0020", " "))


def convert_nano_to_human_time(epoch_time):
    """Convert a nanosecond epoch time to human readable format."""
    return datetime(1601, 1, 1) + timedelta(microseconds=(epoch_time) / 10)


if __name__ == "__main__":
    main()
