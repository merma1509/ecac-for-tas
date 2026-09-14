"""Entry point for the standalone ledger process.

Run as:
    python -m effect_broker.ledger_process [--socket /tmp/ecac-ledger.sock]

The ledger process is an isolated component that runs IndependentEffectLedger
in a separate OS process. Neither the broker nor the executor can mutate
ledger state directly — all mutations go through the IPC interface defined
in effect_broker/ipc.py.

This process is the single writer of truth. Both:
  - broker.commit() (via ProcessLedgerClient)
  - executor.execute() (via same ProcessLedgerClient)
forward their record_* calls here.

Architecture:
    ┌─────────────────────┐     IPC (Unix socket)     ┌─────────────────┐
    │  broker + executor  │ ─────────────────────────►│  Ledger Process │
    └─────────────────────┘                           │                 │
                                                      │  Independent    │
                                                      │  EffectLedger   │
                                                      └─────────────────┘
"""

from __future__ import annotations

import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Standalone IPC ledger process for effect broker.",
    )
    parser.add_argument(
        "--socket",
        default="/tmp/ecac-ledger.sock",
        help="Unix socket path (default: /tmp/ecac-ledger.sock)",
    )
    args = parser.parse_args()

    from effect_broker.ipc import LedgerProcessServer

    server = LedgerProcessServer(socket_path=args.socket)
    try:
        server.run()
    except KeyboardInterrupt:
        print("\nLedger process shutdown.")
        sys.exit(0)


if __name__ == "__main__":
    main()
