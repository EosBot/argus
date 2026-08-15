from subprocess import CompletedProcess
from unittest.mock import patch

from backend.agents.people import PeopleFinder


@patch("backend.agents.people.subprocess.run")
@patch("backend.agents.people.shutil.which", return_value="/usr/bin/sherlock")
def test_username_search_invokes_sherlock_without_shell(_which, run) -> None:
    run.return_value = CompletedProcess(
        [], 0, stdout="https://example.test/user\n", stderr=""
    )

    result = PeopleFinder._run_native_package("researcher", "username")

    assert result and result["source"] == "sherlock"
    args, kwargs = run.call_args
    assert args[0][:2] == ["sherlock", "researcher"]
    assert "--proxy" in args[0]
    assert args[0][args[0].index("--proxy") + 1].startswith("socks5h://")
    assert "shell" not in kwargs
    assert kwargs["timeout"] == 90


@patch("backend.agents.people.shutil.which", return_value="/usr/bin/holehe")
def test_email_package_without_verified_proxy_is_not_executed(_which) -> None:
    assert PeopleFinder._run_native_package("person@example.org", "email") is None
