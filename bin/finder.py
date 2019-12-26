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


import os
import re
import git
import json
import sys
import argparse
import typing
from langdetect import detect as langdetect

PATTERNS_PATH="../patterns"

parser = argparse.ArgumentParser(description = "Finding potential software vulnerabilities from git commit messages.", epilog = "More info: https://github.com/cve-search/git-vuln-finder")
parser.add_argument("-v", help="increase output verbosity", action="store_true")
parser.add_argument("-r", type=str, help="git repository to analyse")
parser.add_argument("-o", type=str, help="Output format: [json]", default="json")
parser.add_argument("-s", type=str, help="State of the commit found", default="under-review")
parser.add_argument("-p", type=str, help="Matching pattern to use: [vulnpatterns, cryptopatterns, cpatterns] - the pattern 'all' is used to match all the patterns at once.", default="vulnpatterns")
parser.add_argument("-c", help="output only a list of the CVE pattern found in commit messages (disable by default)", action="store_true")
parser.add_argument("-t", help="Include tags matching a specific commit", action="store_true")
args = parser.parse_args()


def build_pattern(pattern_file):
    fp = open(pattern_file, "r")
    rex = ""
    try:
        prefix_fp = open(pattern_file + ".prefix", "r")
        rex += prefix_fp.read()
        prefix_fp.close()
    except:
        pass
    
    for line in fp.readlines():
        rex += line.rstrip() + "|"
    rex = rex[:-1] # We remove the extra '|
    fp.close()

    try:
        suffix_fp = open(pattern_file + ".suffix", "r")
        rex += suffix_fp.read()
        suffix_fp.close()
    except:
        pass
    
    return rex
    
def get_patterns(patterns_path=PATTERNS_PATH):
    patterns = {}
    for root, dirs, files in os.walk(patterns_path):
        path = root.split(os.sep)
        for f in files:
            if f.endswith(".prefix") or f.endswith(".suffix"):
                continue
            npath = root[len(patterns_path):].split(os.sep)
            try:
                npath.remove('')
            except ValueError:
                pass

            lang = npath[0]
            severity = npath[1]
            pattern_category = f
            
            try: # FIXME: Is there a better way?
                a = patterns[lang]
            except KeyError:
                patterns[lang] = {}
            try:
                a = patterns[lang][severity]
            except KeyError:
                patterns[lang][severity] = {}
            try:
                a = patterns[lang][severity][pattern_category]
            except KeyError:
                rex = build_pattern(root + os.sep + f)
                patterns[lang][severity][pattern_category] = re.compile(rex)

    return patterns

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


found = 0
potential_vulnerabilities = {}
cve_found = set()

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

def summary(commit, branch, pattern, origin=None):
    rcommit = commit
    cve = extract_cve(rcommit.message)
    if origin is not None:
        origin = origin
        if origin.find('github.com'):
            origin_github_api = origin.split(':')[1]
            (org_name, repo_name) = origin_github_api.split('/', 1)
            if repo_name.find('.git$'):
                repo_name = re.sub(r".git$","", repo_name)
            origin_github_api = 'https://api.github.com/repos/{}/{}/commits/{}'.format(org_name, repo_name, rcommit.hexsha)

    else:
        origin = 'git origin unknown'
    # deduplication if similar commits on different branches
    if rcommit.hexsha in potential_vulnerabilities:
       potential_vulnerabilities[rcommit.hexsha]['branches'].append(branch)
    else:
        potential_vulnerabilities[rcommit.hexsha] = {}
        potential_vulnerabilities[rcommit.hexsha]['message'] = rcommit.message
        potential_vulnerabilities[rcommit.hexsha]['language'] = langdetect(rcommit.message)
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
        potential_vulnerabilities[rcommit.hexsha]['origin'] = origin
        if origin_github_api:
            potential_vulnerabilities[commit.hexsha]['origin-github-api'] = origin_github_api
        potential_vulnerabilities[rcommit.hexsha]['tags'] = []
        if args.t:
            if repo.commit(rcommit).hexsha in tagmap:
                potential_vulnerabilities[rcommit.hexsha]['tags'] = tagmap[repo.commit(rcommit).hexsha]
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
        for v in m:
            cve_found.add(v)
        return m
    else:
        return None

repo_heads = repo.heads
repo_heads_names = [h.name for h in repo_heads]
print(repo_heads_names, file=sys.stderr)
origin = repo.remotes.origin.url
if args.t:
    tagmap = {}
    for t in repo.tags:
        tagmap.setdefault(repo.commit(t).hexsha, []).append(str(t))

for branch in repo_heads_names:
    commits = list(repo.iter_commits(branch))
    defaultpattern
    for commit in commits:
        if isinstance(defaultpattern, typing.Pattern):
            ret = find_vuln(commit, pattern=defaultpattern)
            if ret:
                rcommit = ret['commit']
                summary(rcommit, branch, defaultpattern, origin=origin)
                found += 1
        elif isinstance(defaultpattern, list):
            for p in defaultpattern:
                ret = find_vuln(commit, pattern=p)
                if ret:
                    rcommit = ret['commit']
                    summary(rcommit, branch, p, origin=origin)
                    found += 1
if not args.c:
    print(json.dumps(potential_vulnerabilities))
elif args.c:
    print(json.dumps(list(cve_found)))

print("{} CVE referenced found in commit(s)".format(len(list(cve_found))), file=sys.stderr)
print("Total potential vulnerability found in {} commit(s)".format(found), file=sys.stderr)
