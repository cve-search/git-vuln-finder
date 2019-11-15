# git-vuln-finder

Finding potential software vulnerabilities from git commit messages. The output format is a JSON with the associated commit which could contain a fix regarding
a software vulnerability. The search is based on a set of regular expressions against the commit messages only.

# Requirements

- Python 3
- GitPython

# Usage

~~~bash
usage: finder.py [-h] [-v] [-r R] [-o O] [-s S] [-p P]

Finding potential software vulnerabilities from git commit messages.

optional arguments:
  -h, --help  show this help message and exit
  -v          increase output verbosity
  -r R        git repository to analyse
  -o O        Output format: [json]
  -s S        State of the commit found
  -p P        Matching pattern to use: [vulnpatterns, cryptopatterns,
              cpatterns]
~~~

# Patterns

git-vuln-finder comes with 3 default patterns which can be selected to find the potential vulnerabilities described in the commit messages such as:

- `vulnpatterns` is a generic vulnerability pattern especially targeting web application and generic security commit message. Based on an academic paper.
- `cryptopatterns` is a vulnerability pattern for cryptographic errors mentioned in commit messages.
- `cpatterns` is a set of standard vulnerability patterns see for C/C++-like languages.

## A sample partial output from Curl git repository

~~~bash
python3 finder.py -r /home/adulau/git/curl | jq .
...
  "6df916d751e72fc9a1febc07bb59c4ddd886c043": {
    "message": "loadlibrary: Only load system DLLs from the system directory\n\nInspiration provided by: Daniel Stenberg and Ray Satiro\n\nBug: https://curl.haxx.se/docs/adv_20160530.html\n\nRef: Windows DLL hijacking with curl, CVE-2016-4802\n",
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
    "pattern-matches": "hijack"
  },
  "c2b3f264cb5210f82bdc84a3b89250a611b68dd3": {
    "message": "CONNECT_ONLY: don't close connection on GSS 401/407 reponses\n\nPreviously, connections were closed immediately before the user had a\nchance to extract the socket when the proxy required Negotiate\nauthentication.\n\nThis regression was brought in with the security fix in commit\n79b9d5f1a42578f\n\nCloses #655\n",
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
    "pattern-matches": "security "
  },
...
~~~

# License and author(s)

This software is free software and licensed under the AGPL version 3.

Copyright (c) 2019 Alexandre Dulaunoy - https://github.com/adulau/

# References

- [Notes](https://gist.github.com/adulau/dce5a6ca5c65017869bb01dfee576303#file-finding-vuln-git-commit-messages-md)
- https://csce.ucmss.com/cr/books/2017/LFS/CSREA2017/ICA2077.pdf (mainly using CVE referenced in the commit message) - archive (http://archive.is/xep9o)
- https://asankhaya.github.io/pdf/automated-identification-of-security-issues-from-commit-messages-and-bug-reports.pdf (2 main regexps)


