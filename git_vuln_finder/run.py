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

import sys
import git
import typing
from git_vuln_finder import get_patterns, find_vuln, find_vuln_event, summary, summary_event


def find(
    repo,
    tags_matching=False,
    commit_state="under-review",
    verbose=False,
    defaultpattern="all",
):
    # Initialization of the variables for the results
    repo = git.Repo(repo)
    found = 0
    all_potential_vulnerabilities = {}
    all_cve_found = set()

    # Initialization of the patterns
    patterns = get_patterns()
    vulnpatterns = patterns["en"]["medium"]["vuln"]
    cryptopatterns = patterns["en"]["medium"]["crypto"]
    cpatterns = patterns["en"]["medium"]["c"]

    if defaultpattern == "vulnpatterns":
        defaultpattern = vulnpatterns
    elif defaultpattern == "cryptopatterns":
        defaultpattern = cryptopatterns
    elif defaultpattern == "cpatterns":
        defaultpattern = cpatterns
    elif defaultpattern == "all":
        defaultpattern = [vulnpatterns, cryptopatterns, cpatterns]

    repo_heads = repo.heads
    repo_heads_names = [h.name for h in repo_heads]
    print(repo_heads_names, file=sys.stderr)
    origin = repo.remotes.origin.url
    tagmap = {}
    if tags_matching:
        for t in repo.tags:
            tagmap.setdefault(repo.commit(t).hexsha, []).append(str(t))

    for branch in repo_heads_names:
        commits = list(repo.iter_commits(branch))
        defaultpattern
        for commit in commits:
            if isinstance(defaultpattern, typing.Pattern):
                ret = find_vuln(commit, pattern=defaultpattern, verbose=verbose)
                if ret:
                    rcommit = ret["commit"]
                    _, potential_vulnerabilities, cve_found = summary(
                        repo,
                        rcommit,
                        branch,
                        tagmap,
                        defaultpattern,
                        origin=origin,
                        vuln_match=ret["match"],
                        tags_matching=tags_matching,
                        commit_state=commit_state,
                    )
                    all_potential_vulnerabilities.update(potential_vulnerabilities)
                    all_cve_found.update(cve_found)
                    found += 1
            elif isinstance(defaultpattern, list):
                for p in defaultpattern:
                    ret = find_vuln(commit, pattern=p, verbose=verbose)
                    if ret:
                        rcommit = ret["commit"]
                        _, potential_vulnerabilities, cve_found = summary(
                            repo,
                            rcommit,
                            branch,
                            tagmap,
                            p,
                            origin=origin,
                            vuln_match=ret["match"],
                            tags_matching=tags_matching,
                            commit_state=commit_state,
                        )
                        all_potential_vulnerabilities.update(potential_vulnerabilities)
                        all_cve_found.update(cve_found)
                        found += 1

        return all_potential_vulnerabilities, all_cve_found, found

def find_event(commit, element):
    # Initialization of the variables for the results
    found = 0
    all_potential_vulnerabilities = {}
    all_cve_found = set()

    # Initialization of the patterns
    patterns = get_patterns()
    vulnpatterns = patterns["en"]["medium"]["vuln"]
    cryptopatterns = patterns["en"]["medium"]["crypto"]
    cpatterns = patterns["en"]["medium"]["c"]

    defaultpattern = [vulnpatterns, cryptopatterns, cpatterns]
    
    for p in defaultpattern:
        ret = find_vuln_event(commit["message"], pattern=p)
        if ret:
            potential_vulnerabilities, cve_found = summary_event(
                commit,
                p,
                element,
                vuln_match=ret["match"]
            )
            all_potential_vulnerabilities.update(potential_vulnerabilities)
            all_cve_found.update(cve_found)
            found += 1

    return all_potential_vulnerabilities, all_cve_found, found
