from __future__ import annotations

import argparse
import logging
import sys
import time

from . import __version__, blaze, nucleus, qos, redirector, telemetry_stub
from .analyze import analyze_file
from .certs import ensure_certs
from .config import load_config
from .server import Server, make_tls_context

BANNER = """
fifa17-friendlies {ver}  --  Blaze preAuth handler (eksperymentalny)
  redirector : {bind}:{rport}   (game asks {host})
  blaze      : {bind}:{bport}   (advertised as {adv}:{bport}, secure={secure})
  qos (http) : {bind}:{qport}
  nucleus    : {bind}:{nport}   (atrapa, HTTP)
  telemetry  : {bind}:{tport}   (atrapa, accept+close - rl.data.ea.com / pin-river.data.ea.com)
  captures   : {logs}
Start FIFA 17 now. Press Ctrl+C to stop.
"""


def cmd_certs(args) -> int:
    cfg = load_config()
    if args.protossl_bypass:
        cfg.cert_sig_hash = "protossl-bypass"
    elif args.sha1:
        cfg.cert_sig_hash = "sha1"
    paths = ensure_certs(cfg, force=args.force or args.sha1 or args.protossl_bypass)
    for name, p in paths.items():
        print(f"{name:11s} {p}")
    return 0


def cmd_run(args) -> int:
    cfg = load_config()
    if args.secure is not None:
        cfg.blaze_secure = args.secure == "1"
    if args.bind:
        cfg.bind_address = args.bind
    if args.no_chain:
        cfg.cert_send_chain = False
    ensure_certs(cfg)
    ctx = make_tls_context(cfg)
    rsrv = Server("redirector", cfg.bind_address, cfg.redirector_port,
                  lambda c, a: redirector.handle(c, a, cfg, ctx)).start()
    # ZMIANA: probe.handle (tylko nagrywal) -> blaze.handle (parsuje TDF i ODPOWIADA na preAuth/ping)
    psrv = Server("blaze", cfg.bind_address, cfg.blaze_port,
                  lambda c, a: blaze.handle(c, a, cfg, ctx)).start()
    qsrv = Server("qos", cfg.bind_address, qos.QOS_PORT,
                  lambda c, a: qos.handle(c, a, cfg, ctx)).start()
    nsrv = Server("nucleus", cfg.bind_address, cfg.nucleus_port,
                  lambda c, a: nucleus.handle(c, a, cfg)).start()
    # DODANE: atrapa telemetrii EA (rl.data.ea.com / pin-river.data.ea.com -> 127.0.0.1 przez
    # IP/Hosts switches RPCS3). Sesja 9 / Tor 2: zamiast accept+close teraz robimy prawdziwy
    # handshake TLS i odpowiadamy HTTP 200 OK -- testujemy hipoteze, ze SeasonalPlayDownloader
    # czeka na udana transakcje telemetrii zanim odpyta Stats (patrz docs/HANDOFF.md).
    tsrv = Server("telemetry", cfg.bind_address, cfg.telemetry_port,
                  lambda c, a: telemetry_stub.handle(c, a, cfg, ctx)).start()
    print(BANNER.format(ver=__version__, bind=cfg.bind_address, rport=rsrv.port, host=cfg.redirector_host,
                        bport=psrv.port, adv=cfg.blaze_advertise_host, secure=cfg.blaze_secure,
                        qport=qsrv.port, nport=nsrv.port, tport=tsrv.port, logs=cfg.log_dir_path))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nstopping")
        rsrv.stop()
        psrv.stop()
        qsrv.stop()
        nsrv.stop()
        tsrv.stop()
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
    p.add_argument("--protossl-bypass", action="store_true",
                    help="sign with a bogus algorithm OID that trips the old EA ProtoSSL "
                         "cert-verify bug (Aim4kill/Bug_OldProtoSSL); try this if --sha1 "
                         "doesn't get past ClientHello->ServerHelloDone")
    p.set_defaults(fn=cmd_certs)

    p = sub.add_parser("run", help="start redirector + Blaze preAuth handler")
    p.add_argument("--secure", choices=["0", "1"], help="advertise plain (0) or TLS (1) main connection")
    p.add_argument("--bind", help="interface to listen on (default from config)")
    p.add_argument("--no-chain", action="store_true",
                    help="send only the leaf certificate, not leaf+CA (some old TLS stacks "
                         "choke on the extra self-signed CA cert)")
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
