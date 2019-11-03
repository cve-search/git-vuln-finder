#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Finding potential software vulnerabilities from git commit messages
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# This software is part of cve-search.org
#
# Copyright (c) 2019 Alexandre Dulaunoy - a@foo.be


import re
import git
import json
import sys
import argparse

parser = argparse.ArgumentParser(description = "Finding potential software vulnerabilities from git commit messages.", epilog = "More info: https://github.com/cve-search/git-vuln-finder")
parser.add_argument("-v", help="increase output verbosity", action="store_true")
parser.add_argument("-r", type=str, help="git repository to analyse")
parser.add_argument("-o", type=str, help="Output format: [json]", default="json")
parser.add_argument("-s", type=str, help="State of the commit found", default="under-review")
args = parser.parse_args()

vulnpatterns = re.compile("(?i)(denial of service |\bXX E\b|remote code execution|\bopen redirect|OSVDB|\bvuln|\bCVE\b |\bXSS\b|\bReDoS\b|\bNVD\b|malicious|x−frame−options|attack|cross site |exploit|malicious|directory traversal |\bRCE\b|\bdos\b|\bXSRF \b|\bXSS\b|clickjack|session.fixation|hijack|\badvisory|\binsecure |security |\bcross−origin\b|unauthori[z|s]ed |infinite loop)")

if not args.r:
    parser.print_usage()
    parser.exit()
else:
    repo = git.Repo(args.r)


found = 0
potential_vulnerabilities = {}


def find_vuln(commit):
    m = vulnpatterns.search(commit.message)
    if m:
        if args.v:
            print("Match found: {}".format(m.group(0)), file=sys.stderr)
            print(commit.message, file=sys.stderr)
            print("---", file=sys.stderr)
        ret = {}
        ret['commit'] = commit
        ret['match'] = m.group(1)
        return ret
    else:
        # print(commit.message)
        return None
        # print("Nothing match")


repo_heads = repo.heads
repo_heads_names = [h.name for h in repo_heads]
print(repo_heads_names, file=sys.stderr)


for branch in repo_heads_names:
    commits = list(repo.iter_commits(branch))

    for commit in commits:
        ret = find_vuln(commit)
        if ret:
            #print("Vulnerability found: {}".format(ret))
            #print(ret.hexsha)
            rcommit = ret['commit']
            # Deduplication of commits on different branches
            if rcommit.hexsha in potential_vulnerabilities:
                potential_vulnerabilities[rcommit.hexsha]['branches'].append(branch)
            else:
                potential_vulnerabilities[rcommit.hexsha] = {}
                potential_vulnerabilities[rcommit.hexsha]['message'] = rcommit.message
                potential_vulnerabilities[rcommit.hexsha]['commit-id'] = rcommit.hexsha
                potential_vulnerabilities[rcommit.hexsha]['summary'] = rcommit.summary
                potential_vulnerabilities[rcommit.hexsha]['stats'] = rcommit.stats.total
                potential_vulnerabilities[rcommit.hexsha]['author'] = rcommit.author.name
                potential_vulnerabilities[rcommit.hexsha]['author-email'] = rcommit.author.email
                potential_vulnerabilities[rcommit.hexsha]['authored_date'] = rcommit.authored_date
                potential_vulnerabilities[rcommit.hexsha]['committed_date'] = rcommit.committed_date
                potential_vulnerabilities[rcommit.hexsha]['branches'] = []
                potential_vulnerabilities[rcommit.hexsha]['branches'].append(branch)
                potential_vulnerabilities[rcommit.hexsha]['pattern-matches'] = ret['match']
                potential_vulnerabilities[rcommit.hexsha]['state'] = args.s
                found += 1

print(json.dumps(potential_vulnerabilities))
print("Total potential vulnerability found in {} commit(s)".format(found), file=sys.stderr)
