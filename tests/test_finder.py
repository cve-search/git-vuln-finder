

from git_vuln_finder import find


def test_find_vuln(clone_curl):
    all_potential_vulnerabilities, all_cve_found, found = find("./test_repos/curl/")

    #assert len(list(all_cve_found)) == 64
    assert "CVE-2018-1000122" in all_cve_found
