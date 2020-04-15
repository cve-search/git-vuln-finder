# git-vuln-finder

![git-vuln-finder logo](https://raw.githubusercontent.com/cve-search/git-vuln-finder/f22077452c37e110bff0564e1f7b34637dc726c3/doc/logos/git-vuln-finder-small.png)

[![Workflow](https://github.com/cve-search/git-vuln-finder/workflows/Python%20application/badge.svg)](https://github.com/cve-search/git-vuln-finder/actions?query=workflow%3A%22Python+application%22)

Finding potential software vulnerabilities from git commit messages.
The output format is a JSON with the associated commit which could contain a
fix regarding a software vulnerability. The search is based on a set of regular
expressions against the commit messages only. If CVE IDs are present, those are
added automatically in the output.

# Requirements

- jq (``sudo apt install jq``)


# Installation

## Use it as a library

git-vuln-finder can be install with poetry. If you don't have poetry installed, you can do the following `curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python`.

~~~bash
$ poetry install
$ poetry shell
$ git-vuln-finder -h
~~~

You can also use ``pip``. Then just import it:

~~~python
Python 3.8.0 (default, Dec 11 2019, 21:43:13)
[GCC 9.2.1 20191008] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from git_vuln_finder import find
>>> all_potential_vulnerabilities, all_cve_found, found = find("~/git/curl")

>>> [commit for commit, summary in all_potential_vulnerabilities.items() if summary['state'] == 'cve-assigned']
['9069838b30fb3b48af0123e39f664cea683254a5', 'facb0e4662415b5f28163e853dc6742ac5fafb3d',
... snap ...
 '8a75dbeb2305297640453029b7905ef51b87e8dd', '1dc43de0dccc2ea7da6dddb7b98f8d7dcf323914', '192c4f788d48f82c03e9cef40013f34370e90737', '2eb8dcf26cb37f09cffe26909a646e702dbcab66', 'fa1ae0abcde5df8d0b3283299e3f246bedf7692c', 'c11c30a8c8d727dcf5634fa0cc6ee0b4b77ddc3d', '75ca568fa1c19de4c5358fed246686de8467c238', 'a20daf90e358c1476a325ea665d533f7a27e3364', '042cc1f69ec0878f542667cb684378869f859911']

 >>> print(json.dumps(all_potential_vulnerabilities['9069838b30fb3b48af0123e39f664cea683254a5'], sort_keys=True, indent=4, separators=(",", ": ")))
 {
     "author": "Daniel Stenberg",
     "author-email": "daniel@haxx.se",
     "authored_date": 1567544372,
     "branches": [
         "master"
     ],
     "commit-id": "9069838b30fb3b48af0123e39f664cea683254a5",
     "committed_date": 1568009674,
     "cve": [
         "CVE-2019-5481",
         "CVE-2019-5481"
     ],
     "language": "en",
     "message": "security:read_data fix bad realloc()\n\n... that could end up a double-free\n\nCVE-2019-5481\nBug: https://curl.haxx.se/docs/CVE-2019-5481.html\n",
     "origin": "https://github.com/curl/curl.git",
     "origin-github-api": "https://api.github.com/repos///github.com/curl/curl/commits/9069838b30fb3b48af0123e39f664cea683254a5",
     "pattern-matches": [
         "double-free"
     ],
     "pattern-selected": "(?i)(double[-| ]free|buffer overflow|double free|race[-| ]condition)",
     "state": "cve-assigned",
     "stats": {
         "deletions": 4,
         "files": 1,
         "insertions": 2,
         "lines": 6
     },
     "summary": "security:read_data fix bad realloc()",
     "tags": []
 }
~~~


## Use it as a command line tool

~~~bash
$ pipx install git-vuln-finder
$ git-vuln-finder --help
~~~

You can also use pip.
``pipx`` installs scripts (system wide available) provided by Python packages
into separate virtualenvs to shield them from your system and each other.


### Usage

~~~bash
usage: git-vuln-finder [-h] [-v] [-r R] [-o O] [-s S] [-p P] [-c] [-t]

Finding potential software vulnerabilities from git commit messages.

optional arguments:
  -h, --help  show this help message and exit
  -v          increase output verbosity
  -r R        git repository to analyse
  -o O        Output format: [json]
  -s S        State of the commit found
  -p P        Matching pattern to use: [vulnpatterns, cryptopatterns,
              cpatterns] - the pattern 'all' is used to match all the patterns
              at once.
  -c          output only a list of the CVE pattern found in commit messages
              (disable by default)
  -t          Include tags matching a specific commit

More info: https://github.com/cve-search/git-vuln-finder
~~~


# Patterns

git-vuln-finder comes with 3 default patterns which can be selected to find the potential vulnerabilities described in the commit messages such as:

- [`vulnpatterns`](https://github.com/cve-search/git-vuln-finder/blob/master/patterns/en/medium/vuln) is a generic vulnerability pattern especially targeting web application and generic security commit message. Based on an academic paper.
- [`cryptopatterns`](https://github.com/cve-search/git-vuln-finder/blob/master/patterns/en/medium/crypto) is a vulnerability pattern for cryptographic errors mentioned in commit messages.
- [`cpatterns`](https://github.com/cve-search/git-vuln-finder/blob/master/patterns/en/medium/c) is a set of standard vulnerability patterns see for C/C++-like languages.


## A sample partial output from Curl git repository

~~~bash
$ git-vuln-finder -r ~/git/curl | jq .
...
 "6df916d751e72fc9a1febc07bb59c4ddd886c043": {
    "message": "loadlibrary: Only load system DLLs from the system directory\n\nInspiration provided by: Daniel Stenberg and Ray Satiro\n\nBug: https://curl.haxx.se/docs/adv_20160530.html\n\nRef: Windows DLL hijacking with curl, CVE-2016-4802\n",
    "language": "en",
    "commit-id": "6df916d751e72fc9a1febc07bb59c4ddd886c043",
    "summary": "loadlibrary: Only load system DLLs from the system directory",
    "stats": {
      "insertions": 180,
      "deletions": 8,
      "lines": 188,
      "files": 7
    },
    "author": "Steve Holme",
    "author-email": "steve_holme@hotmail.com",
    "authored_date": 1464555460,
    "committed_date": 1464588867,
    "branches": [
      "master"
    ],
    "pattern-selected": "(?i)(denial of service |\bXXE\b|remote code execution|\bopen redirect|OSVDB|\bvuln|\bCVE\b |\bXSS\b|\bReDoS\b|\bNVD\b|malicious|x−frame−options|attack|cross site |exploit|malicious|directory traversal |\bRCE\b|\bdos\b|\bXSRF \b|\bXSS\b|clickjack|session.fixation|hijack|\badvisory|\binsecure |security |\bcross−origin\b|unauthori[z|s]ed |infinite loop)",
    "pattern-matches": [
      "hijack"
    ],
    "origin": "git@github.com:curl/curl.git",
    "origin-github-api": "https://api.github.com/repos/curl/curl/commits/6df916d751e72fc9a1febc07bb59c4ddd886c043",
    "tags": [],
    "cve": [
      "CVE-2016-4802"
    ],
    "state": "cve-assigned"
  },
  "c2b3f264cb5210f82bdc84a3b89250a611b68dd3": {
    "message": "CONNECT_ONLY: don't close connection on GSS 401/407 reponses\n\nPreviously, connections were closed immediately before the user had a\nchance to extract the socket when the proxy required Negotiate\nauthentication.\n\nThis regression was brought in with the security fix in commit\n79b9d5f1a42578f\n\nCloses #655\n",
    "language": "en",
    "commit-id": "c2b3f264cb5210f82bdc84a3b89250a611b68dd3",
    "summary": "CONNECT_ONLY: don't close connection on GSS 401/407 reponses",
    "stats": {
      "insertions": 4,
      "deletions": 2,
      "lines": 6,
      "files": 1
    },
    "author": "Marcel Raad",
    "author-email": "raad@teamviewer.com",
    "authored_date": 1455523116,
    "committed_date": 1461704516,
    "branches": [
      "master"
    ],
    "pattern-selected": "(?i)(denial of service |\bXXE\b|remote code execution|\bopen redirect|OSVDB|\bvuln|\bCVE\b |\bXSS\b|\bReDoS\b|\bNVD\b|malicious|x−frame−options|attack|cross site |exploit|malicious|directory traversal |\bRCE\b|\bdos\b|\bXSRF \b|\bXSS\b|clickjack|session.fixation|hijack|\badvisory|\binsecure |security |\bcross−origin\b|unauthori[z|s]ed |infinite loop)",
    "pattern-matches": [
      "security "
    ],
    "origin": "git@github.com:curl/curl.git",
    "origin-github-api": "https://api.github.com/repos/curl/curl/commits/c2b3f264cb5210f82bdc84a3b89250a611b68dd3",
    "tags": [],
    "state": "under-review"
  },
...
~~~

- Extracting CVE id(s) from git messages

~~~json
  "98d132cf6a879faf0147aa83ea0c07ff326260ed": {
    "message": "Add a macro for testing assertion in both debug and production builds\n\nIf we have an assert then in a debug build we want an abort() to occur.\nIn a production build we wan
t the function to return an error.\n\nThis introduces a new macro to assist with that. The idea is to replace\nexisting use of OPENSSL_assert() with this new macro. The problem with\nOPENSSL
_assert() is that it aborts() on an assertion failure in both debug\nand production builds. It should never be a library's decision to abort a\nprocess (we don't get to decide when to kill t
he life support machine or\nthe nuclear reactor control system). Additionally if an attacker can\ncause a reachable assert to be hit then this can be a source of DoS attacks\ne.g. see CVE-20
17-3733, CVE-2015-0293, CVE-2011-4577 and CVE-2002-1568.\n\nReviewed-by: Tim Hudson <tjh@openssl.org>\n(Merged from https://github.com/openssl/openssl/pull/3496)",
    "commit-id": "98d132cf6a879faf0147aa83ea0c07ff326260ed",
    "summary": "Add a macro for testing assertion in both debug and production builds",
    "stats": {
      "insertions": 18,
      "deletions": 0,
      "lines": 18,
      "files": 1
    },
    "author": "Matt Caswell",
    "author-email": "matt@openssl.org",
    "authored_date": 1495182637,
    "committed_date": 1495457671,
    "branches": [
      "master"
    ],
    "pattern-selected": "(?i)(denial of service |\bXXE\b|remote code execution|\bopen redirect|OSVDB|\bvuln|\bCVE\b |\bXSS\b|\bReDoS\b|\bNVD\b|malicious|x−frame−options|attack|cross site |ex
ploit|malicious|directory traversal |\bRCE\b|\bdos\b|\bXSRF \b|\bXSS\b|clickjack|session.fixation|hijack|\badvisory|\binsecure |security |\bcross−origin\b|unauthori[z|s]ed |infinite loop)",
    "pattern-matches": [
      "attack"
    ],
    "cve": [
      "CVE-2017-3733",
      "CVE-2015-0293",
      "CVE-2011-4577",
      "CVE-2002-1568"
    ],
    "state": "cve-assigned"
  }
~~~


# Running the tests

~~~bash
$ pytest
~~~


# License and author(s)

This software is free software and licensed under the AGPL version 3.

Copyright (c) 2019-2020 Alexandre Dulaunoy - https://github.com/adulau/


# Acknowledgment

- Thanks to [Jean-Louis Huynen](https://github.com/gallypette) for the discussions about the crypto vulnerability patterns.
- Thanks to [Sebastien Tricaud](https://github.com/stricaud) for the discussions regarding native language, commit messages and external patterns.
- Thanks to [Cedric Bonhomme](https://github.com/cedricbonhomme) to make git-vuln-finder a Python library, add tests and improve the overall installation process.


# Contributing

We welcome contributions for the software and especially additional vulnerability patterns. Every contributors will be added in the [AUTHORS file](./AUTHORS) and
collectively own this open source software. The contributors acknowledge the [Developer Certificate of Origin](https://developercertificate.org/).


# References

- [Notes](https://gist.github.com/adulau/dce5a6ca5c65017869bb01dfee576303#file-finding-vuln-git-commit-messages-md)
- https://csce.ucmss.com/cr/books/2017/LFS/CSREA2017/ICA2077.pdf (mainly using CVE referenced in the commit message) - archive (http://archive.is/xep9o)
- https://asankhaya.github.io/pdf/automated-identification-of-security-issues-from-commit-messages-and-bug-reports.pdf (2 main regexps)
