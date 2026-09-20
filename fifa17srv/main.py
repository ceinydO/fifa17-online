from __future__ import annotations

import argparse
import logging
import sys
import time

from . import __version__, probe, redirector
from .analyze import analyze_file
from .certs import ensure_certs
from .config import load_config
from .server import Server, make_tls_context

BANNER = """
fifa17-friendlies {ver}  --  protocol discovery mode
  redirector : {bind}:{rport}   (game asks {host})
  blaze probe: {bind}:{bport}   (advertised as {adv}:{bport}, secure={secure})
  captures   : {logs}
Start FIFA 17 now. Press Ctrl+C to stop.
"""


def cmd_certs(args) -> int:
    cfg = load_config()
    if args.sha1:
        cfg.cert_sig_hash = "sha1"
    paths = ensure_certs(cfg, force=args.force or args.sha1)
    for name, p in paths.items():
        print(f"{name:11s} {p}")
    return 0


def cmd_run(args) -> int:
    cfg = load_config()
    if args.secure is not None:
        cfg.blaze_secure = args.secure == "1"
    if args.bind:
        cfg.bind_address = args.bind
    ensure_certs(cfg)
    ctx = make_tls_context(cfg)
    rsrv = Server("redirector", cfg.bind_address, cfg.redirector_port,
                  lambda c, a: redirector.handle(c, a, cfg, ctx)).start()
    psrv = Server("blaze-probe", cfg.bind_address, cfg.blaze_port,
                  lambda c, a: probe.handle(c, a, cfg, ctx)).start()
    print(BANNER.format(ver=__version__, bind=cfg.bind_address, rport=rsrv.port, host=cfg.redirector_host,
                        bport=psrv.port, adv=cfg.blaze_advertise_host, secure=cfg.blaze_secure,
                        logs=cfg.log_dir_path))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nstopping")
        rsrv.stop()
        psrv.stop()
    return 0


def cmd_analyze(args) -> int:
    return analyze_file(args.file)


def cmd_selftest(args) -> int:
    from .selftest import run_selftest
    return run_selftest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="fifa17srv", description="FIFA 17 friendlies server (discovery phase)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("certs", help="generate local CA + server certificate")
    p.add_argument("--force", action="store_true", help="regenerate even if present")
    p.add_argument("--sha1", action="store_true", help="sign with SHA-1 (for very old TLS stacks)")
    p.set_defaults(fn=cmd_certs)

    p = sub.add_parser("run", help="start redirector + capture probe")
    p.add_argument("--secure", choices=["0", "1"], help="advertise plain (0) or TLS (1) main connection")
    p.add_argument("--bind", help="interface to listen on (default from config)")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("analyze", help="inspect a captured *_c2s.bin file")
    p.add_argument("file")
    p.set_defaults(fn=cmd_analyze)

    p = sub.add_parser("selftest", help="run built-in tests (no game needed)")
    p.set_defaults(fn=cmd_selftest)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
