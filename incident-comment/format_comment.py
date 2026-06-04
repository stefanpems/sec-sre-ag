"""
Sentinel Incident Comment Formatter
====================================
Detects content type (plain text / Markdown / HTML), converts to a format
suitable for the narrow Activities panel (~400 px single column) in
Microsoft Sentinel, and writes a JSON body file ready for the API call.

Zero external dependencies — Python 3 stdlib only.

Usage:
    python3 format_comment.py <input_file> --output-json <output.json> \
        [--type auto|text|markdown|html] \
        [--api graph|sentinel] \
        [--max-chars N] \
        [--title TEXT]

Exit codes:
    0  success
    1  argument / runtime error
    2  content exceeds --max-chars after conversion
"""

import argparse
import json
import os
import re
import sys
import uuid
from html.parser import HTMLParser
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════

SENTINEL_MAX_CHARS = 30_000          # hard API limit per comment
COLUMN_MAX_PX = 400                  # Activities panel width estimate

# HTML tags that signal the input is already HTML
_HTML_BLOCK_TAGS = re.compile(
    r"<(?:div|table|tr|td|th|thead|tbody|ul|ol|li|p|br|h[1-6]|"
    r"pre|code|blockquote|img|a|span|section|article|header|footer|"
    r"style|script|html|head|body|strong|em|b|i)\b",
    re.IGNORECASE,
)

# Markdown signal patterns (each hit = +1 signal score)
_MD_SIGNALS = [
    re.compile(r"^#{1,6}\s", re.MULTILINE),           # headings
    re.compile(r"^\s*[-*+]\s", re.MULTILINE),          # unordered lists
    re.compile(r"^\s*\d+\.\s", re.MULTILINE),          # ordered lists
    re.compile(r"\*\*[^*]+\*\*"),                       # bold
    re.compile(r"(?<!\*)\*(?!\*)[^*]+\*(?!\*)"),        # italic
    re.compile(r"`[^`]+`"),                             # inline code
    re.compile(r"^\s*>", re.MULTILINE),                 # blockquote
    re.compile(r"^\s*[-*_]{3,}\s*$", re.MULTILINE),    # horizontal rule
    re.compile(r"\[([^\]]+)\]\(([^)]+)\)"),             # links
    re.compile(r"!\[([^\]]*)\]\(([^)]+)\)"),            # images
    re.compile(r"^\|.*\|.*\|", re.MULTILINE),           # tables
    re.compile(r"```"),                                  # fenced code
    re.compile(r"~~[^~]+~~"),                           # strikethrough
]

# ═══════════════════════════════════════════════════════════════════
# CONTENT TYPE DETECTION
# ═══════════════════════════════════════════════════════════════════


def detect_type(text: str) -> str:
    """Return 'html', 'markdown', or 'text'."""
    stripped = text.strip()

    # Strong HTML signals: DOCTYPE, <html, or ≥3 distinct HTML tags
    if re.search(r"<!DOCTYPE", stripped, re.IGNORECASE):
        return "html"
    if re.search(r"<html[\s>]", stripped, re.IGNORECASE):
        return "html"

    html_tags_found = set()
    for m in _HTML_BLOCK_TAGS.finditer(stripped):
        tag = m.group(0).lower().lstrip("<")
        html_tags_found.add(tag)
    if len(html_tags_found) >= 3:
        return "html"

    # Markdown signals — need ≥2 distinct signals
    md_score = sum(1 for pat in _MD_SIGNALS if pat.search(stripped))
    if md_score >= 2:
        return "markdown"

    return "text"


# ═══════════════════════════════════════════════════════════════════
# MARKDOWN → HTML
# ═══════════════════════════════════════════════════════════════════

def _md_inline(line: str) -> str:
    """Convert inline Markdown elements to HTML."""
    # Images first (before links, since ![alt](url) contains [alt](url))
    line = re.sub(
        r"!\[([^\]]*)\]\(([^)]+)\)",
        r'<img src="\2" alt="\1" style="max-width:100%;height:auto;">',
        line,
    )
    # Links
    line = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        r'<a href="\2" target="_blank">\1</a>',
        line,
    )
    # Bold
    line = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", line)
    # Strikethrough
    line = re.sub(r"~~([^~]+)~~", r"<del>\1</del>", line)
    # Italic (single *)
    line = re.sub(r"(?<!\*)\*(?!\*)([^*]+)\*(?!\*)", r"<em>\1</em>", line)
    # Inline code
    line = re.sub(r"`([^`]+)`", r"<code>\1</code>", line)
    return line


def _heading_level(hashes: str) -> int:
    """Downscale headings: MD h1→h3, h2→h4, h3→h5, rest→h6."""
    n = len(hashes)
    return min(n + 2, 6)


def markdown_to_html(md: str) -> str:
    """Convert Markdown text to HTML optimized for a narrow column."""
    lines = md.split("\n")
    out: list[str] = []
    in_code = False
    code_buf: list[str] = []
    in_table = False
    table_buf: list[str] = []
    in_list: str | None = None  # 'ul' or 'ol'
    list_buf: list[str] = []

    def flush_list():
        nonlocal in_list, list_buf
        if in_list and list_buf:
            tag = in_list
            items = "".join(f"<li>{_md_inline(i)}</li>" for i in list_buf)
            out.append(f"<{tag}>{items}</{tag}>")
        in_list = None
        list_buf = []

    def flush_table():
        nonlocal in_table, table_buf
        if not table_buf:
            in_table = False
            return
        rows = table_buf[:]
        table_buf.clear()
        in_table = False

        # Parse header
        header_cells = [c.strip() for c in rows[0].strip("|").split("|")]
        # Skip separator row (row[1] if it matches ---|--)
        data_start = 1
        if len(rows) > 1 and re.match(r"^\|?[\s:]*-+", rows[1]):
            data_start = 2

        html = '<div style="overflow-x:auto;"><table style="border-collapse:collapse;width:100%;font-size:13px;">'
        html += "<thead><tr>"
        for cell in header_cells:
            html += f'<th style="border:1px solid #555;padding:4px 8px;text-align:left;background:#2a2a2a;">{_md_inline(cell)}</th>'
        html += "</tr></thead><tbody>"
        for row in rows[data_start:]:
            cells = [c.strip() for c in row.strip("|").split("|")]
            html += "<tr>"
            for cell in cells:
                html += f'<td style="border:1px solid #555;padding:4px 8px;">{_md_inline(cell)}</td>'
            html += "</tr>"
        html += "</tbody></table></div>"
        out.append(html)

    for line in lines:
        # Fenced code blocks
        if line.strip().startswith("```"):
            if in_code:
                code_text = "\n".join(code_buf)
                out.append(
                    f'<pre style="background:#1e1e1e;padding:8px;border-radius:4px;'
                    f'overflow-x:auto;white-space:pre-wrap;word-wrap:break-word;'
                    f'font-size:12px;"><code>{code_text}</code></pre>'
                )
                code_buf.clear()
                in_code = False
            else:
                flush_list()
                flush_table()
                in_code = True
            continue

        if in_code:
            code_buf.append(line)
            continue

        stripped = line.strip()

        # Table rows
        if re.match(r"^\|.*\|", stripped):
            flush_list()
            if not in_table:
                in_table = True
            table_buf.append(stripped)
            continue
        elif in_table:
            flush_table()

        # Headings
        m_head = re.match(r"^(#{1,6})\s+(.*)", stripped)
        if m_head:
            flush_list()
            lvl = _heading_level(m_head.group(1))
            text = _md_inline(m_head.group(2))
            out.append(f"<h{lvl}>{text}</h{lvl}>")
            continue

        # Horizontal rule
        if re.match(r"^[-*_]{3,}\s*$", stripped):
            flush_list()
            out.append("<hr>")
            continue

        # Blockquote
        if stripped.startswith(">"):
            flush_list()
            bq_text = _md_inline(stripped.lstrip("> "))
            out.append(
                f'<blockquote style="border-left:3px solid #666;padding-left:10px;'
                f'margin:6px 0;color:#aaa;">{bq_text}</blockquote>'
            )
            continue

        # Unordered list item
        m_ul = re.match(r"^\s*[-*+]\s+(.*)", stripped)
        if m_ul:
            if in_list == "ol":
                flush_list()
            in_list = "ul"
            list_buf.append(m_ul.group(1))
            continue

        # Ordered list item
        m_ol = re.match(r"^\s*\d+\.\s+(.*)", stripped)
        if m_ol:
            if in_list == "ul":
                flush_list()
            in_list = "ol"
            list_buf.append(m_ol.group(1))
            continue

        # If we were in a list and hit a non-list line, flush
        if in_list:
            flush_list()

        # Blank line
        if not stripped:
            continue

        # Regular paragraph
        out.append(f"<p>{_md_inline(stripped)}</p>")

    # Flush any remaining state
    if in_code and code_buf:
        code_text = "\n".join(code_buf)
        out.append(
            f'<pre style="background:#1e1e1e;padding:8px;border-radius:4px;'
            f'overflow-x:auto;white-space:pre-wrap;word-wrap:break-word;'
            f'font-size:12px;"><code>{code_text}</code></pre>'
        )
    flush_list()
    flush_table()

    body = "\n".join(out)
    return (
        f'<div style="font-family:Segoe UI,sans-serif;font-size:14px;'
        f'line-height:1.5;color:#e0e0e0;max-width:100%;'
        f'word-wrap:break-word;overflow-wrap:break-word;">'
        f"{body}</div>"
    )


# ═══════════════════════════════════════════════════════════════════
# HTML → ADAPTED HTML  (single-column / narrow panel)
# ═══════════════════════════════════════════════════════════════════


class _TagStripper(HTMLParser):
    """Strip specific wrapper tags while keeping inner content."""

    STRIP_TAGS = {"html", "head", "body", "style", "script", "meta", "link", "title"}

    def __init__(self):
        super().__init__()
        self._pieces: list[str] = []
        self._skip_depth = 0
        self._skip_tags: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() in self.STRIP_TAGS:
            self._skip_depth += 1
            self._skip_tags.append(tag.lower())
            # For style/script, skip ALL nested content
            return
        if self._skip_depth and self._skip_tags[-1] in ("style", "script"):
            return
        attr_str = ""
        for k, v in attrs:
            if v is None:
                attr_str += f" {k}"
            else:
                attr_str += f' {k}="{v}"'
        self._pieces.append(f"<{tag}{attr_str}>")

    def handle_endtag(self, tag):
        if self._skip_depth and self._skip_tags and self._skip_tags[-1] == tag.lower():
            self._skip_depth -= 1
            self._skip_tags.pop()
            return
        if self._skip_depth and self._skip_tags and self._skip_tags[-1] in ("style", "script"):
            return
        self._pieces.append(f"</{tag}>")

    def handle_data(self, data):
        if self._skip_depth and self._skip_tags and self._skip_tags[-1] in ("style", "script"):
            return
        self._pieces.append(data)

    def handle_entityref(self, name):
        self._pieces.append(f"&{name};")

    def handle_charref(self, name):
        self._pieces.append(f"&#{name};")

    def handle_comment(self, data):
        pass  # strip HTML comments

    def handle_decl(self, decl):
        pass  # strip DOCTYPE

    def get_result(self) -> str:
        return "".join(self._pieces)


def adapt_html(html: str) -> str:
    """Adapt HTML for the narrow Sentinel Activities panel."""
    # 1. Strip document wrappers (html, head, body, style, script)
    stripper = _TagStripper()
    stripper.feed(html)
    result = stripper.get_result().strip()

    # 2. Clamp fixed widths > 400px to 100%
    result = re.sub(
        r'(width\s*:\s*)(\d{3,})\s*px',
        lambda m: f"{m.group(1)}100%" if int(m.group(2)) > COLUMN_MAX_PX else m.group(0),
        result,
        flags=re.IGNORECASE,
    )

    # 3. Convert multi-column grids to single column
    result = re.sub(
        r'grid-template-columns\s*:\s*[^;"]+',
        "grid-template-columns: 1fr",
        result,
        flags=re.IGNORECASE,
    )

    # 4. Wrap bare <table> in scrollable container (skip if already wrapped)
    def _wrap_table(m):
        full = m.group(0)
        # Check if the 50 chars before <table contain overflow
        start = max(0, m.start() - 60)
        prefix = html[start : m.start()]
        if "overflow" in prefix.lower():
            return full
        return f'<div style="overflow-x:auto;">{full}</div>'

    result = re.sub(
        r"<table\b[^>]*>.*?</table>",
        _wrap_table,
        result,
        flags=re.DOTALL | re.IGNORECASE,
    )

    # 5. Make images responsive
    result = re.sub(
        r"(<img\b[^>]*?)(/?>)",
        lambda m: (
            m.group(1) + ' style="max-width:100%;height:auto;"' + m.group(2)
            if "max-width" not in m.group(1).lower()
            else m.group(0)
        ),
        result,
        flags=re.IGNORECASE,
    )

    # 6. Downscale headers: h1→h3, h2→h4
    result = re.sub(r"<h1\b", "<h3", result, flags=re.IGNORECASE)
    result = re.sub(r"</h1>", "</h3>", result, flags=re.IGNORECASE)
    result = re.sub(r"<h2\b", "<h4", result, flags=re.IGNORECASE)
    result = re.sub(r"</h2>", "</h4>", result, flags=re.IGNORECASE)

    # 7. Ensure target="_blank" on links
    def _fix_link(m):
        tag = m.group(0)
        if 'target=' in tag.lower():
            return tag
        return tag[:-1] + ' target="_blank">'

    result = re.sub(r"<a\b[^>]*>", _fix_link, result, flags=re.IGNORECASE)

    # 8. Add word-wrap to <pre> blocks
    def _fix_pre(m):
        tag = m.group(0)
        if "word-wrap" in tag.lower() or "white-space" in tag.lower():
            return tag
        if "style=" in tag.lower():
            return tag.replace("style=\"", 'style="white-space:pre-wrap;word-wrap:break-word;', 1)
        return tag[:-1] + ' style="white-space:pre-wrap;word-wrap:break-word;">'

    result = re.sub(r"<pre\b[^>]*>", _fix_pre, result, flags=re.IGNORECASE)

    # 9. Wrap in a column container
    result = (
        f'<div style="font-family:Segoe UI,sans-serif;font-size:14px;'
        f'line-height:1.5;max-width:100%;'
        f'word-wrap:break-word;overflow-wrap:break-word;">'
        f"{result}</div>"
    )

    return result


# ═══════════════════════════════════════════════════════════════════
# TITLE BANNER (optional)
# ═══════════════════════════════════════════════════════════════════

def _make_title_banner(title: str) -> str:
    """Return an HTML banner for the comment title."""
    return (
        f'<div style="background:#0078d4;color:#fff;padding:6px 12px;'
        f'border-radius:4px;margin-bottom:10px;font-weight:600;'
        f'font-size:14px;">{title}</div>'
    )


# ═══════════════════════════════════════════════════════════════════
# BUILD JSON BODY
# ═══════════════════════════════════════════════════════════════════

def build_graph_body(content: str) -> dict:
    """Build the body for POST /security/incidents/{id}/comments."""
    return {
        "@odata.type": "microsoft.graph.security.alertComment",
        "comment": content,
    }


def build_sentinel_body(content: str) -> dict:
    """Build the body for PUT .../incidents/{guid}/comments/{commentId}."""
    return {
        "properties": {
            "message": content,
        }
    }


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Format content for a Sentinel incident comment.",
    )
    parser.add_argument("input_file", help="Path to the input file (text/md/html)")
    parser.add_argument(
        "--output-json",
        required=True,
        help="Path to write the JSON body file",
    )
    parser.add_argument(
        "--type",
        choices=["auto", "text", "markdown", "html"],
        default="auto",
        help="Content type (default: auto-detect)",
    )
    parser.add_argument(
        "--api",
        choices=["graph", "sentinel"],
        default="graph",
        help="Target API format (default: graph)",
    )
    parser.add_argument(
        "--max-chars",
        type=int,
        default=SENTINEL_MAX_CHARS,
        help=f"Max character limit (default: {SENTINEL_MAX_CHARS})",
    )
    parser.add_argument(
        "--title",
        default=None,
        help="Optional title banner prepended to the comment",
    )

    args = parser.parse_args()

    # Read input
    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    raw = input_path.read_text(encoding="utf-8")
    if not raw.strip():
        print("ERROR: Input file is empty.", file=sys.stderr)
        sys.exit(1)

    # Detect or use specified type
    content_type = args.type if args.type != "auto" else detect_type(raw)

    # Convert
    if content_type == "text":
        converted = raw  # pass through as-is
    elif content_type == "markdown":
        converted = markdown_to_html(raw)
    elif content_type == "html":
        converted = adapt_html(raw)
    else:
        converted = raw

    # Prepend title banner if specified
    if args.title:
        banner = _make_title_banner(args.title)
        converted = banner + converted

    # Check length
    if len(converted) > args.max_chars:
        print(
            f"ERROR: Converted content is {len(converted)} chars, "
            f"exceeds limit of {args.max_chars}.",
            file=sys.stderr,
        )
        sys.exit(2)

    # Build JSON body
    if args.api == "graph":
        body = build_graph_body(converted)
    else:
        body = build_sentinel_body(converted)

    # Write output
    out_path = Path(args.output_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(body, ensure_ascii=False, indent=2), encoding="utf-8")

    # Report
    print(f"OK | type={content_type} | api={args.api} | chars={len(converted)} | output={out_path}")


if __name__ == "__main__":
    main()
