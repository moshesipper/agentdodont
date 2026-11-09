"""CLI:  python -m agentdodont run "turn on dark mode"
       python -m agentdodont doctor
       python -m agentdodont log logs/<session>
       python -m agentdodont relay        # API key stays here; the phone app talks to this
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from . import ui
from .adb import AdbError, Device


def cmd_doctor(args) -> int:
    dev = Device(args.serial)
    ok = True

    def check(label, fn):
        nonlocal ok
        try:
            val = fn()
            print(f"  ok   {label}: {val}")
            return val
        except Exception as e:  # noqa: BLE001 - diagnostic output
            ok = False
            print(f"  FAIL {label}: {e}")
            return None

    print(f"adb: {dev.adb}")
    devices = check("devices", dev.list_devices)
    if devices is not None:
        ready = [s for s, st in devices if st == "device"]
        for s, st in devices:
            if st == "unauthorized":
                print(f"  !!   {s} is unauthorized: unlock the phone and accept the USB debugging prompt")
        if not ready:
            print("  FAIL no authorized device. Enable Developer options + USB debugging and plug in via USB.")
            return 1
        if len(ready) > 1 and not args.serial:
            print(f"  FAIL several devices connected ({', '.join(ready)}); pass --serial")
            return 1
    check("model", lambda: f"{dev.getprop('ro.product.manufacturer')} {dev.getprop('ro.product.model')}")
    check("android", lambda: f"{dev.getprop('ro.build.version.release')} (SDK {dev.getprop('ro.build.version.sdk')}), One UI {dev.getprop('ro.build.version.oneui') or '?'}")
    check("screen size", dev.screen_size)
    check("packages", lambda: f"{len(dev.packages())} installed")
    t0 = time.time()
    xml = check("uiautomator dump", lambda: dev.dump_ui())
    if xml:
        s = ui.parse(xml, dev.screen_size())
        print(f"       {len(s.elements)} elements in {time.time() - t0:.1f}s, foreground {s.package}")
        if args.verbose:
            print(s.render())
    check("screencap", lambda: f"{len(dev.screencap()) // 1024} KB PNG")
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
    print(f"  {'ok  ' if has_key else 'warn'} Anthropic credentials in env: {has_key}")
    try:
        import PIL  # noqa: F401
        print("  ok   Pillow installed (screenshots get downscaled)")
    except ImportError:
        print("  warn Pillow not installed: screenshots are sent full size (pip install pillow)")
    print("all good" if ok else "some checks failed")
    return 0 if ok else 1


def cmd_screen(args) -> int:
    dev = Device(args.serial)
    print(ui.parse(dev.dump_ui(), dev.screen_size()).render())
    return 0


def cmd_run(args) -> int:
    from .agent import DEFAULT_MODEL, Agent
    from .audit import AuditLog
    from .policy import Policy

    dev = Device(args.serial)
    if not dev.serial:  # record which phone the session ran on
        ready = [s for s, st in dev.list_devices() if st == "device"]
        if len(ready) == 1:
            dev.serial = ready[0]
    policy = Policy.load(args.policy, ask_all=args.ask_all)
    log = AuditLog(args.log_dir, save_screens=args.save_screens)
    agent = Agent(dev, policy, log, model=args.model or DEFAULT_MODEL, effort=args.effort,
                  max_steps=args.max_steps, dry_run=args.dry_run, fallbacks=not args.no_fallbacks)
    print(f"task: {args.task}\nlog:  {log.dir}\n")
    try:
        result = agent.run(args.task)
    except KeyboardInterrupt:
        log.event("stop", step=agent.step, reason="interrupted by user")
        print("\ninterrupted")
        return 130
    except AdbError as e:
        log.event("stop", step=agent.step, reason=f"adb error: {e}")
        print(f"adb error: {e}")
        return 2
    finally:
        log.close()
    u = agent.usage
    print(f"\nsteps: {result.steps}   tokens in {u['input']} (cache read {u['cache_read']}, write {u['cache_write']}) / out {u['output']}")
    print(f"log: {result.log_dir}   (python -m agentdodont log {result.log_dir})")
    return 0 if result.success else 1


def cmd_suite(args) -> int:
    from .agent import DEFAULT_MODEL
    from .suite import TASKS, format_report, run_suite

    if args.list:
        for t in TASKS:
            print(f"{t.name:<24} {t.prompt if isinstance(t.prompt, str) else '(generated prompt)'}")
        return 0
    dev = Device(args.serial)
    if not dev.serial:
        ready = [s for s, st in dev.list_devices() if st == "device"]
        if len(ready) == 1:
            dev.serial = ready[0]
    names = [n.strip() for n in args.tasks.split(",")] if args.tasks else None
    report = run_suite(dev, args.model or DEFAULT_MODEL, args.effort, names, args.repeat)
    print(format_report(report))
    return 0 if all(r["passed"] is not False for r in report["rows"]) else 1


def cmd_log(args) -> int:
    from pathlib import Path

    from .audit import show

    root = Path(args.log_dir)
    sessions = sorted(p for p in root.glob("*") if (p / "actions.jsonl").exists()) if root.exists() else []
    if args.list:
        for p in sessions:
            print(p)
        return 0
    if args.session in (None, "latest"):
        if not sessions:
            print(f"no sessions found in {root}")
            return 1
        target = sessions[-1]
    else:
        target = Path(args.session)
        if not target.exists() and (root / args.session).exists():
            target = root / args.session
    if not target.exists():
        print(f"no such session: {args.session}")
        if sessions:
            print("available sessions:\n  " + "\n  ".join(str(p) for p in sessions[-10:]))
        return 1
    print(f"session: {target}\n")
    print(show(target))
    return 0


def cmd_relay(args) -> int:
    import threading
    from pathlib import Path

    from .pairing import DeviceRegistry, PairingSession, ensure_cert, lan_ip, pair_link, qr_ascii
    from .relay import Relay, ensure_token, keep_phone_linked, make_server, make_tls_server, read_properties

    state = Path(args.state_dir)
    devices = DeviceRegistry(state / "devices.json")
    if args.devices:
        for d in devices.devices or [{"id": "-", "name": "no paired devices", "paired": "", "last_seen": ""}]:
            print(f"{d['id']:<4} {d['name']:<24} paired {d['paired']}  last seen {d['last_seen'] or 'never'}")
        return 0
    if args.revoke:
        ok = devices.revoke(args.revoke)
        print(f"revoked {args.revoke}" if ok else f"no device {args.revoke}")
        return 0 if ok else 1

    props_path = Path(args.properties)
    api_key = os.environ.get("ANTHROPIC_API_KEY") or read_properties(props_path).get("anthropic.apiKey")
    if not api_key:
        print(f"no API key: set ANTHROPIC_API_KEY or put anthropic.apiKey=... in {props_path}")
        return 1
    token, created = ensure_token(props_path, rotate=args.new_token)
    relay = Relay(api_key, token, daily_budget_usd=args.budget, state_dir=Path(args.log_dir), devices=devices)
    server = make_server(relay, port=args.port)
    tls = None
    if args.lan or args.pair:
        cert, key, fp = ensure_cert(state)
        host = args.pair_host or f"{lan_ip()}:{args.lan_port}"
        tls = make_tls_server(relay, "0.0.0.0", args.lan_port, cert, key)
        threading.Thread(target=tls.serve_forever, daemon=True).start()
        print(f"Wi-Fi relay (TLS) on {host}   certificate {fp[:16]}…   paired devices: {len(devices.devices)}")
        if args.pair:
            relay.pairing = PairingSession(fp)
            link = pair_link(host, relay.pairing.code, fp)
            print("\nScan with the phone's camera, or type in Agent Do/Don't:  pair " + host + " " + relay.pairing.code)
            print(qr_ascii(link))
            print(f"code {relay.pairing.code} (works once, for 5 minutes)   fingerprint {fp[:8]}-{fp[8:16]}\n")
    print(f"relay on 127.0.0.1:{args.port}   budget ${args.budget:.2f}/day (spent today ${relay.spent_today():.2f})")
    print(f"log: {relay.log_path}  (metadata only)")
    if created:
        print(f"  new relay token generated (saved in {props_path}); the old one no longer works")
    stop = threading.Event()
    threading.Thread(target=keep_phone_linked, args=(Device(args.serial).adb, args.serial, args.port, token, stop),
                     daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nrelay stopped")
    finally:
        stop.set()
        server.server_close()
        if tls:
            tls.server_close()
    return 0


def cmd_mcp_proxy(args) -> int:
    from .mcp_proxy import main as proxy_main  # imported here: the other commands don't need it
    return proxy_main(args)


def main(argv: list[str] | None = None) -> int:
    from . import __version__
    p = argparse.ArgumentParser(prog="agentdodont", description="Agent Do/Don't: a rules engine between an AI agent "
                                "and its tools. mcp-proxy guards any MCP server; the other commands drive an Android phone.")
    p.add_argument("--version", action="version", version=f"agentdodont {__version__}")
    p.add_argument("--serial", help="adb device serial (when several are connected)")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run a task on the phone")
    r.add_argument("task")
    r.add_argument("--model", help="Claude model id (default claude-opus-5-5)")
    r.add_argument("--effort", default="medium", choices=["low", "medium", "high", "xhigh", "max"])
    r.add_argument("--max-steps", type=int, default=40)
    r.add_argument("--policy", help="JSON file overriding policy defaults (levels, word lists, packages)")
    r.add_argument("--ask-all", action="store_true", help="ask before every action")
    r.add_argument("--dry-run", action="store_true", help="observe and decide, but never touch the phone")
    r.add_argument("--save-screens", action="store_true", help="save every UI dump into the log dir")
    r.add_argument("--log-dir", default="logs")
    r.add_argument("--no-fallbacks", action="store_true", help="disable server-side refusal fallback")
    r.set_defaults(fn=cmd_run)

    d = sub.add_parser("doctor", help="check adb, device, and credentials")
    d.add_argument("-v", "--verbose", action="store_true", help="also print the current screen")
    d.set_defaults(fn=cmd_doctor)

    st = sub.add_parser("suite", help="run the repeatable task suite with ground-truth checks")
    st.add_argument("--model", help="Claude model id (default claude-opus-5-5)")
    st.add_argument("--effort", default="medium", choices=["low", "medium", "high", "xhigh", "max"])
    st.add_argument("--tasks", help="comma-separated task names (default: all)")
    st.add_argument("--repeat", type=int, default=1)
    st.add_argument("--list", action="store_true", help="list tasks and exit")
    st.set_defaults(fn=cmd_suite)

    rl = sub.add_parser("relay", help="hold the API key for the phone app (tunnelled over USB)")
    rl.add_argument("--port", type=int, default=8787)
    rl.add_argument("--budget", type=float, default=2.0, help="daily spend cap in USD (default 2)")
    rl.add_argument("--properties", default="android/local.properties", help="where the key and token live")
    rl.add_argument("--log-dir", default="logs")
    rl.add_argument("--new-token", action="store_true", help="replace the phone token (no rebuild needed)")
    rl.add_argument("--lan", action="store_true", help="also serve paired phones over Wi-Fi (TLS)")
    rl.add_argument("--lan-port", type=int, default=8788)
    rl.add_argument("--pair", action="store_true", help="show a QR code to pair a phone (implies --lan)")
    rl.add_argument("--pair-host", help="address to put in the QR code (default: this laptop's LAN IP)")
    rl.add_argument("--devices", action="store_true", help="list paired phones and exit")
    rl.add_argument("--revoke", metavar="ID", help="unpair a phone (see --devices) and exit")
    rl.add_argument("--state-dir", default=".relay", help="where the certificate and paired devices live")
    rl.set_defaults(fn=cmd_relay)

    s = sub.add_parser("screen",help="print the current screen as the model sees it")
    s.set_defaults(fn=cmd_screen)

    lg = sub.add_parser("log", help="show a session log as a 'why did you do that?' trace")
    lg.add_argument("session", nargs="?", help="session folder, its name, or 'latest' (default: latest)")
    lg.add_argument("--list", action="store_true", help="list all sessions")
    lg.add_argument("--log-dir", default="logs")
    lg.set_defaults(fn=cmd_log)

    mp = sub.add_parser("mcp-proxy", help="put the rules engine between an MCP client and an MCP server")
    mp.add_argument("--rules", help="JSON rules file (levels, allowed_sites, known_recipients, tools...)")
    mp.add_argument("--name", help="the server's name in questions and the log (default: the command)")
    mp.add_argument("--log", default=str(__import__("pathlib").Path.home() / ".agentdodont" / "mcp-audit.jsonl"),
                    help="audit log (JSONL)")
    mp.add_argument("--session", help="share taint with other proxies in this session: default = every proxy started "
                                      "by the same client; a name = every proxy given that name; none = don't share")
    mp.add_argument("server", nargs=argparse.REMAINDER, help="-- then the MCP server command and its arguments")
    mp.set_defaults(fn=cmd_mcp_proxy)

    args = p.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):  # Windows consoles default to cp1252; UI text is Unicode
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
