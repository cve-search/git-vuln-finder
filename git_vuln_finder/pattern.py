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


import os
import re
from collections import defaultdict


def tree():
    """Autovivification.
    Call it a tree or call it 'patterns'.
    """
    return defaultdict(tree)


PATTERNS_PATH = os.path.dirname(os.path.abspath(__file__)) + "/patterns"


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
    rex = rex[:-1]  # We remove the extra '|
    fp.close()

    try:
        suffix_fp = open(pattern_file + ".suffix", "r")
        rex += suffix_fp.read()
        suffix_fp.close()
    except:
        pass

    return rex


def get_patterns(patterns_path=PATTERNS_PATH):
    patterns = tree()
    for root, dirs, files in os.walk(patterns_path):
        path = root.split(os.sep)
        for f in files:
            if f.endswith(".prefix") or f.endswith(".suffix"):
                continue
            npath = root[len(patterns_path) :].split(os.sep)
            try:
                npath.remove("")
            except ValueError:
                pass

            lang = npath[0]
            severity = npath[1]
            pattern_category = f

            rex = build_pattern(root + os.sep + f)
            patterns[lang][severity][pattern_category] = re.compile(rex)

    return patterns
