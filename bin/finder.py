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


import git
import json
import sys
import argparse
import typing

from git_vuln_finder import get_patterns, find_vuln, summary


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
    args = parser.parse_args()

    patterns = get_patterns()
    vulnpatterns = patterns["en"]["medium"]["vuln"]
    cryptopatterns = patterns["en"]["medium"]["crypto"]
    cpatterns = patterns["en"]["medium"]["c"]

    if args.p == "vulnpatterns":
        defaultpattern = vulnpatterns
    elif args.p == "cryptopatterns":
        defaultpattern = cryptopatterns
    elif args.p == "cpatterns":
        defaultpattern = cpatterns
    elif args.p == "all":
        defaultpattern = [vulnpatterns, cryptopatterns, cpatterns]
    else:
        parser.print_usage()
        parser.exit()

    if not args.r:
        parser.print_usage()
        parser.exit()
    else:
        repo = git.Repo(args.r)

    # Initialization of the variables for the results
    found = 0
    all_potential_vulnerabilities = {}
    cve_found = set()

    repo_heads = repo.heads
    repo_heads_names = [h.name for h in repo_heads]
    print(repo_heads_names, file=sys.stderr)
    origin = repo.remotes.origin.url
    tagmap = {}
    if args.t:
        for t in repo.tags:
            tagmap.setdefault(repo.commit(t).hexsha, []).append(str(t))

    for branch in repo_heads_names:
        commits = list(repo.iter_commits(branch))
        defaultpattern
        for commit in commits:
            if isinstance(defaultpattern, typing.Pattern):
                ret = find_vuln(commit, pattern=defaultpattern, verbose=args.v)
                if ret:
                    rcommit = ret["commit"]
                    _, potential_vulnerabilities = summary(
                        repo,
                        rcommit,
                        branch,
                        tagmap,
                        defaultpattern,
                        origin=origin,
                        vuln_match=ret["match"],
                        tags_matching=args.t,
                        commit_state=args.s,
                    )
                    all_potential_vulnerabilities.update(potential_vulnerabilities)
                    found += 1
            elif isinstance(defaultpattern, list):
                for p in defaultpattern:
                    ret = find_vuln(commit, pattern=p, verbose=args.v)
                    if ret:
                        rcommit = ret["commit"]
                        _, potential_vulnerabilities = summary(
                            repo,
                            rcommit,
                            branch,
                            tagmap,
                            p,
                            origin=origin,
                            vuln_match=ret["match"],
                            tags_matching=args.t,
                            commit_state=args.s,
                        )
                        all_potential_vulnerabilities.update(potential_vulnerabilities)
                        found += 1

    if not args.c:
        print(json.dumps(all_potential_vulnerabilities))
    elif args.c:
        print(json.dumps(list(cve_found)))

    print(
        "{} CVE referenced found in commit(s)".format(len(list(cve_found))),
        file=sys.stderr,
    )
    print(
        "Total potential vulnerability found in {} commit(s)".format(found),
        file=sys.stderr,
    )
