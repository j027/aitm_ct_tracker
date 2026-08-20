import os
import subprocess
import sys
import tempfile

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _import_config(env_overrides, cwd=PROJECT_ROOT):
    env = os.environ.copy()
    env["PYTHONPATH"] = PROJECT_ROOT
    env["CERTSTREAM_WS_URL"] = "ws://127.0.0.1:8080/"
    for key, value in env_overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return subprocess.run(
        [sys.executable, "-c", "import ct_watcher.config"],
        env=env,
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def _no_channels():
    return {
        "DISCORD_WEBHOOK": "",
        "APPRISE_URLS": "",
        "EMAIL_ENABLED": "false",
        "SMTP_ENABLED": "false",
    }


class TestConfigImport:
    def test_no_notification_channel_is_allowed(self):
        result = _import_config(_no_channels())
        assert result.returncode == 0, result.stderr

    def test_email_only_is_allowed(self):
        overrides = _no_channels()
        overrides["EMAIL_ENABLED"] = "true"
        overrides["SMTP_ENABLED"] = "true"
        result = _import_config(overrides)
        assert result.returncode == 0, result.stderr

    def test_missing_certstream_ws_url_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = _import_config({"CERTSTREAM_WS_URL": None}, cwd=tmpdir)
        assert result.returncode != 0
        assert "CERTSTREAM_WS_URL" in result.stderr
