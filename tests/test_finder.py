

from git_vuln_finder import find


def test_find_vuln():
    all_potential_vulnerabilities, all_cve_found, found = find("test_repos/curl")

    assert len(list(all_cve_found)) == 63
