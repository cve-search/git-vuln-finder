#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Finding potential software vulnerabilities from git commit messages
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# This software is part of cve-search.org
#
# Copyright (c) 2019-2020 Alexandre Dulaunoy - a@foo.be


import json
import sys
import argparse

from git_vuln_finder import find, find_event


def main():
    """Point of entry for the script.
    """
    # Parsing arguments
    parser = argparse.ArgumentParser(
        description="Finding potential software vulnerabilities from git commit messages.",
        epilog="More info: https://github.com/cve-search/git-vuln-finder",
    )
    parser.add_argument("-v", help="increase output verbosity", action="store_true")
    parser.add_argument("-r", type=str, help="git repository to analyse")
    parser.add_argument("-o", type=str, help="Output format: [json]", default="json")
    parser.add_argument(
        "-s", type=str, help="State of the commit found", default="under-review"
    )
    parser.add_argument(
        "-p",
        type=str,
        help="Matching pattern to use: [vulnpatterns, cryptopatterns, cpatterns] - the pattern 'all' is used to match all the patterns at once.",
        default="vulnpatterns",
    )
    parser.add_argument(
        "-c",
        help="output only a list of the CVE pattern found in commit messages (disable by default)",
        action="store_true",
    )
    parser.add_argument(
        "-t", help="Include tags matching a specific commit", action="store_true"
    )
    parser.add_argument(
        "-gh", help="special option for gharchive, pass a file containing a PushEvent in JSON format"
    )
    args = parser.parse_args()

    if args.p not in ["vulnpatterns", "cryptopatterns", "cpatterns", "all"]:
        parser.print_usage()
        parser.exit()

    if not args.r and not args.gh:
        parser.print_usage()
        parser.exit()

    if args.gh:
        with open(args.gh, "r") as read_file:
            event = json.load(read_file)

        for element in event:
            for i in range(0,len(element["payload"]["commits"])):
                all_potential_vulnerabilities, all_cve_found, found = find_event(element["payload"]["commits"][i], element)

    else:
        # Launch the process
        all_potential_vulnerabilities, all_cve_found, found = find(
            args.r,
            tags_matching=args.t,
            commit_state=args.s,
            verbose=args.v,
            defaultpattern=args.p,
        )

    # Output the result as json. Can be piped to another software.
    if not args.c:
        print(json.dumps(all_potential_vulnerabilities))
    elif args.c:
        print(json.dumps(list(all_cve_found)))

    # Output the result to stderr.
    print(
        "{} CVE referenced found in commit(s)".format(len(list(all_cve_found))),
        file=sys.stderr,
    )
    print(
        "Total potential vulnerability found in {} commit(s)".format(found),
        file=sys.stderr,
    )
