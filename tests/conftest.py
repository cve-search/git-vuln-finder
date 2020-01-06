
import os
import pytest

from git import Repo


@pytest.fixture(scope='session')
def clone_curl():
    """Clone the repository of curl for the tests."""
    git_url = 'https://github.com/curl/curl.git'
    repo_dir = './test_repos/curl'
    repo = Repo.clone_from(url=git_url, to_path=repo_dir)
    #repo.heads['curl-7_67_0'].checkout()

    def teardown():
        os.unlink(repo_dir)

    return repo_dir
