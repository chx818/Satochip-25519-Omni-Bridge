"""Safe entry point for the non-destructive VPCD audit.

This file intentionally contains no setup, seed-import, reset, lock, terminate,
or policy-changing operation.  Older versions of this script contained a
``--reset-test-seed`` mode and hard-coded credentials; that mode has been
removed so an accidental invocation cannot modify a card.

The live checks are implemented in ``test_live_card_full.py`` and are limited
to SELECT/status, SecureChannel + PIN verification, read-only SLIP-0010
public-key derivation, Ed25519 signing, X25519 agreement, and read-only
secp256k1 public-key derivation.
"""
import argparse

from test_live_card_full import run_live_test


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the safe, non-destructive Satochip VPCD audit"
    )
    parser.add_argument(
        "--reset-test-seed",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args(argv)
    if args.reset_test_seed:
        parser.error(
            "destructive seed reset/import has been permanently removed; "
            "use a disposable card and an explicit separate provisioning tool "
            "outside this audit suite"
        )
    return 0 if run_live_test() else 1


if __name__ == "__main__":
    raise SystemExit(main())
