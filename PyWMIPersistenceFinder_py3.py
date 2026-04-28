#!/usr/bin/env python3

#
# PyWMIPersistenceFinder.py
# Version 1.1 - Python 3 port
#
# Original Author:
# David Pany - Mandiant (FireEye) - 2017
# Twitter: @DavidPany
#
# Python 3 port notes:
# - Removed `from __future__ import print_function` (built-in in Python 3)
# - File opened in binary mode ("rb"); all string comparisons use bytes literals (b"...")
# - `" ".join(lines_list)` changed to `b" ".join(lines_list)` (joining bytes objects)
# - `.replace("\n", "")` changed to `.replace(b"\n", b"")`
# - `dict.iteritems()` -> `dict.items()` (iteritems removed in Python 3)
# - `filter(lambda ..., iterable)` replaced with a generator expression
#   (filter() returns an iterator in Python 3, and joining bytes needs explicit handling)
# - Regex patterns that operate on the bytes `potential_page` converted to rb"..." patterns
# - Named groups decoded to str for printing via .decode("utf-8", errors="replace")
# - All membership/substring tests use bytes literals
#

import sys
import re
import string

PRINTABLE_BYTES = set(string.printable.encode('ascii'))


def _decode(b):
    """Decode bytes to str safely."""
    if isinstance(b, bytes):
        return b.decode("utf-8", errors="replace")
    return b or ""


def main():
    """Main function for everything!"""

    if len(sys.argv) < 2:
        print("Usage: PyWMIPersistenceFinder_py3.py <OBJECTS.DATA file>")
        sys.exit(1)

    print("\n Enumerating FilterToConsumerBindings...")

    # Read objects.data 4 lines at a time to look for bindings
    objects_file = open(sys.argv[1], "rb")
    current_line = objects_file.readline()
    lines_list = [current_line]
    current_line = objects_file.readline()
    lines_list.append(current_line)
    current_line = objects_file.readline()
    lines_list.append(current_line)
    current_line = objects_file.readline()
    lines_list.append(current_line)

    # Precompiled match objects (bytes patterns)
    event_consumer_mo = re.compile(rb"([\w\\]*EventConsumer\.Name=\")([\w\s]*)(\")")
    event_filter_mo   = re.compile(rb"(_EventFilter\.Name=\")([\w\s]*)(\")")

    # Dictionaries that will store bindings, consumers, and filters
    bindings_dict = {}
    consumer_dict = {}
    filter_dict   = {}

    while current_line:
        potential_page = b" ".join(lines_list)

        if b"_FilterToConsumerBinding" in potential_page:
            consumer_match = re.search(event_consumer_mo, potential_page)
            filter_match   = re.search(event_filter_mo, potential_page)

            if consumer_match and filter_match:
                event_consumer_name = consumer_match.group(2)  # bytes
                event_filter_name   = filter_match.group(2)    # bytes

                if event_consumer_name not in consumer_dict:
                    consumer_dict[event_consumer_name] = set()
                if event_filter_name not in filter_dict:
                    filter_dict[event_filter_name] = set()

                binding_id = b"%b-%b" % (event_consumer_name, event_filter_name)
                if binding_id not in bindings_dict:
                    bindings_dict[binding_id] = {
                        "event_consumer_name": event_consumer_name,
                        "event_filter_name":   event_filter_name,
                    }

        current_line = objects_file.readline()
        lines_list.append(current_line)
        lines_list.pop(0)

    objects_file.close()

    print(" {} FilterToConsumerBinding(s) Found. Enumerating Filters and Consumers..."
          .format(len(bindings_dict)))

    # Second pass: read again to find consumers and filters
    objects_file = open(sys.argv[1], "rb")
    current_line = objects_file.readline()
    lines_list = [current_line]
    current_line = objects_file.readline()
    lines_list.append(current_line)
    current_line = objects_file.readline()
    lines_list.append(current_line)
    current_line = objects_file.readline()
    lines_list.append(current_line)

    while current_line:
        potential_page = b" ".join(lines_list).replace(b"\n", b"")

        if b"EventConsumer" in potential_page:
            for event_consumer_name in consumer_dict:
                if b"CommandLineEventConsumer" in potential_page:
                    consumer_mo = re.compile(
                        rb"(CommandLineEventConsumer)(\x00\x00)(.*?)(\x00)(.*?)"
                        + re.escape(event_consumer_name)
                        + rb"(\x00\x00)?([^\x00]*)?"
                    )
                    consumer_match = re.search(consumer_mo, potential_page)
                    if consumer_match:
                        noisy_bytes = consumer_match.group(3)
                        # Filter to printable ASCII bytes only
                        clean_str = "".join(
                            chr(b) for b in noisy_bytes if b in PRINTABLE_BYTES
                        )
                        consumer_details = (
                            "\n\t\tConsumer Type: {}\n\t\tArguments: {}".format(
                                _decode(consumer_match.group(1)), clean_str)
                        )
                        g5 = consumer_match.group(6)
                        g7 = consumer_match.group(7)
                        if g5:
                            consumer_details += "\n\t\tConsumer Name: {}".format(_decode(g5))
                        if g7:
                            consumer_details += "\n\t\tOther: {}".format(_decode(g7))
                        consumer_dict[event_consumer_name].add(consumer_details)
                else:
                    consumer_mo = re.compile(
                        rb"(\w*EventConsumer)(.*?)"
                        + re.escape(event_consumer_name)
                        + rb"(\x00\x00)([^\x00]*)(\x00\x00)([^\x00]*)"
                    )
                    consumer_match = re.search(consumer_mo, potential_page)
                    if consumer_match:
                        consumer_details = "{} ~ {} ~ {} ~ {}".format(
                            _decode(consumer_match.group(1)),
                            _decode(event_consumer_name),
                            _decode(consumer_match.group(4)),
                            _decode(consumer_match.group(6)),
                        )
                        consumer_dict[event_consumer_name].add(consumer_details)

        for event_filter_name in filter_dict:
            if event_filter_name in potential_page:
                filter_mo = re.compile(
                    re.escape(event_filter_name) + rb"(\x00\x00)([^\x00]*)(\x00\x00)"
                )
                filter_match = re.search(filter_mo, potential_page)
                if filter_match:
                    filter_details = "\n\t\tFilter name: {}\n\t\tFilter Query: {}".format(
                        _decode(event_filter_name),
                        _decode(filter_match.group(2)),
                    )
                    filter_dict[event_filter_name].add(filter_details)

        current_line = objects_file.readline()
        lines_list.append(current_line)
        lines_list.pop(0)

    objects_file.close()

    # Print results to stdout
    print("\n Bindings:\n")

    for binding_name, binding_details in bindings_dict.items():
        binding_name_str = _decode(binding_name)

        if (
            "BVTConsumer-BVTFilter" in binding_name_str or
            "SCM Event Log Consumer-SCM Event Log Filter" in binding_name_str
        ):
            print(
                " {}\n (Common binding based on consumer and filter names,"
                " possibly legitimate)".format(binding_name_str)
            )
        else:
            print(" {}".format(binding_name_str))

        event_filter_name   = binding_details["event_filter_name"]
        event_consumer_name = binding_details["event_consumer_name"]

        if consumer_dict[event_consumer_name]:
            for event_consumer_details in consumer_dict[event_consumer_name]:
                print("\t Consumer: {}".format(event_consumer_details))
        else:
            print("\t Consumer: {}".format(_decode(event_consumer_name)))

        for event_filter_details in filter_dict[event_filter_name]:
            print("\n\t Filter: {}".format(event_filter_details))

        print()

    print(
        "\n Thanks for using PyWMIPersistenceFinder! Please contact @DavidPany with "
        "questions, bugs, or suggestions.\n\n Please review FireEye's whitepaper "
        "for additional WMI persistence details:\n https://www.fireeye.com/content/dam"
        "/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf"
    )


if __name__ == "__main__":
    main()
