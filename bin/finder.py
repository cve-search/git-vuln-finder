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
import typing

parser = argparse.ArgumentParser(description = "Finding potential software vulnerabilities from git commit messages.", epilog = "More info: https://github.com/cve-search/git-vuln-finder")
parser.add_argument("-v", help="increase output verbosity", action="store_true")
parser.add_argument("-r", type=str, help="git repository to analyse")
parser.add_argument("-o", type=str, help="Output format: [json]", default="json")
parser.add_argument("-s", type=str, help="State of the commit found", default="under-review")
parser.add_argument("-p", type=str, help="Matching pattern to use: [vulnpatterns, cryptopatterns, cpatterns] - the pattern 'all' is used to match all the patterns at once.", default="vulnpatterns")
args = parser.parse_args()

vulnpatterns = re.compile("(?i)(denial of service |\bXXE\b|remote code execution|\bopen redirect|OSVDB|\bvuln|\bCVE\b |\bXSS\b|\bReDoS\b|\bNVD\b|malicious|x−frame−options|attack|cross site |exploit|malicious|directory traversal |\bRCE\b|\bdos\b|\bXSRF \b|\bXSS\b|clickjack|session.fixation|hijack|\badvisory|\binsecure |security |\bcross−origin\b|unauthori[z|s]ed |infinite loop)")

cryptopatterns = re.compile(".*(assessment|lack of|bad|vulnerable|missing|unproper|unsuitable|breakable|broken|weak|incorrect|replace|assessment|pen([\s-]?)test|pentest|penetration([\s-]?)test|report|vulnerablity|replace|fix|issue|fixes|add|remove|check){1,} (crypto|cryptographic|cryptography|encipherement|encryption|ciphers|cipher|AES|DES|3DES|cipher|GPG|PGP|OpenSSL|SSH|wireguard|VPN|CBC|ECB|CTR|key[.|,|\s]|private([\s-]?)key|public([\s-]?)key size|length|strenght|generation|randomness|entropy|prng|rng){1,}")




cpatterns = re.compile("(?i)(double[-| ]free|buffer overflow|double free|race[-| ]condition)")

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


found = 0
potential_vulnerabilities = {}


def find_vuln(commit, pattern=vulnpatterns):
    m = pattern.search(commit.message)
    if m:
        if args.v:
            print("Match found: {}".format(m.group(0)), file=sys.stderr)
            print(commit.message, file=sys.stderr)
            print("---", file=sys.stderr)
        ret = {}
        ret['commit'] = commit
        ret['match'] = m.groups()
        return ret
    else:
        return None

def summary(commit, branch, pattern):
    rcommit = commit
    cve = extract_cve(rcommit.message)
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
        potential_vulnerabilities[rcommit.hexsha]['pattern-selected'] = pattern.pattern
        potential_vulnerabilities[rcommit.hexsha]['pattern-matches'] = ret['match']
        if cve: potential_vulnerabilities[rcommit.hexsha]['cve'] = cve
        if cve:
            potential_vulnerabilities[rcommit.hexsha]['state'] = "cve-assigned"
        else:
            potential_vulnerabilities[rcommit.hexsha]['state'] = args.s

    return rcommit.hexsha

def extract_cve(commit):
    cve_find = re.compile(r'CVE-[1-2]\d{1,4}-\d{1,7}', re.IGNORECASE)
    m = cve_find.findall(commit)
    if m:
        return m
    else:
        return None

repo_heads = repo.heads
repo_heads_names = [h.name for h in repo_heads]
print(repo_heads_names, file=sys.stderr)

for branch in repo_heads_names:
    commits = list(repo.iter_commits(branch))

    defaultpattern
    for commit in commits:
        if isinstance(defaultpattern, typing.Pattern):
            ret = find_vuln(commit, pattern=defaultpattern)
            if ret:
                #print("Vulnerability found: {}".format(ret))
                #print(ret.hexsha)
                rcommit = ret['commit']
                summary(rcommit, branch, defaultpattern)
                # Deduplication of commits on different branches
                found += 1
        elif isinstance(defaultpattern, list):
            for p in defaultpattern:
                ret = find_vuln(commit, pattern=p)
                if ret:
                    rcommit = ret['commit']
                    summary(rcommit, branch, p)
                    found += 1

print(json.dumps(potential_vulnerabilities))

print("Total potential vulnerability found in {} commit(s)".format(found), file=sys.stderr)
