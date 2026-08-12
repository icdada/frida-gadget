"""Tests for scripts.signing."""
import io
import subprocess

from scripts import signing


class FakeStdin:  # pylint: disable=too-few-public-methods
    """Stand-in for sys.stdin with a controllable isatty()."""

    def __init__(self, tty):
        """Record whether this stream should look like a terminal."""
        self.tty = tty

    def isatty(self):
        """Report whether this stream is a terminal."""
        return self.tty


# --- signing -------------------------------------------------------------


def test_passwords_are_redacted():
    """A failing signer must not print the keystore passwords."""
    cmd = ["java", "--ks", "/k.jks", "--ksKeyPass", "hunter2", "--ksPass", "s3cr3t"]

    redacted = signing.redact_passwords(cmd)

    assert "hunter2" not in redacted
    assert "s3cr3t" not in redacted
    assert redacted.count("***") == 2
    assert cmd[-1] == "s3cr3t", "the original command must not be modified"


def test_redaction_survives_a_trailing_flag():
    """A flag without its value must not walk off the end of the list."""
    assert signing.redact_passwords(["java", "--ksPass"]) == ["java", "--ksPass"]


def test_stdin_without_a_terminal(monkeypatch):
    """A pipe cannot answer a password prompt."""
    monkeypatch.setattr("sys.stdin", io.StringIO())
    assert signing.stdin_is_interactive() is False


def test_stdin_that_was_closed(monkeypatch):
    """A closed stream raises rather than answering isatty()."""
    class Closed:  # pylint: disable=too-few-public-methods
        """Raises the way a closed file object does."""

        def isatty(self):
            """Fail the way a closed stream does."""
            raise ValueError("I/O operation on closed file")

    monkeypatch.setattr("sys.stdin", Closed())
    assert signing.stdin_is_interactive() is False


def test_missing_stdin(monkeypatch):
    """Windowed interpreters can leave sys.stdin unset."""
    monkeypatch.setattr("sys.stdin", None)
    assert signing.stdin_is_interactive() is False


def test_signer_keeps_the_pipe_without_a_terminal(monkeypatch):
    """Handing over a stdin nobody can type into would hang the run."""
    captured = {}
    monkeypatch.setattr(signing, "download_signer", lambda: "/signer.jar")
    monkeypatch.setattr("sys.stdin", FakeStdin(tty=False))
    monkeypatch.setattr(signing.subprocess, "Popen", _popen_recorder(captured))

    signing.sign_apk("/out/app.apk", ks="/k.jks")

    assert captured["stdout"] is subprocess.PIPE
    assert captured["input"] == b"\n"


def test_signer_gets_the_terminal_when_there_is_one(monkeypatch):
    """uber-apk-signer prompts for the passwords it was not given."""
    captured = {}
    monkeypatch.setattr(signing, "download_signer", lambda: "/signer.jar")
    monkeypatch.setattr("sys.stdin", FakeStdin(tty=True))
    monkeypatch.setattr(signing.subprocess, "Popen", _popen_recorder(captured))

    signing.sign_apk("/out/app.apk", ks="/k.jks")

    assert captured["stdout"] is None
    assert captured["input"] is None


def test_signer_keeps_the_pipe_when_both_passwords_are_given(monkeypatch):
    """With nothing left to prompt for there is no reason to give up stdout."""
    captured = {}
    monkeypatch.setattr(signing, "download_signer", lambda: "/signer.jar")
    monkeypatch.setattr("sys.stdin", FakeStdin(tty=True))
    monkeypatch.setattr(signing.subprocess, "Popen", _popen_recorder(captured))

    signing.sign_apk("/out/app.apk", ks="/k.jks", ks_pass="a", ks_key_pass="b")

    assert captured["stdout"] is subprocess.PIPE


def _popen_recorder(captured):
    """Build a Popen stand-in recording how the signer was wired up."""
    class FakeProcess:
        """Reports a successful, silent run."""

        returncode = 0

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def communicate(self, data=None):
            """Record what was written to the signer."""
            captured["input"] = data
            return (b"", None)

    def popen(cmd, stdin=None, stdout=None, stderr=None):
        """Record the streams the signer was given."""
        captured.update(cmd=cmd, stdin=stdin, stdout=stdout, stderr=stderr)
        return FakeProcess()

    return popen
