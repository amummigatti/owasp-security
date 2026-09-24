#!/usr/bin/env python3
# Author: Akshatha Mummigatti
"""Read the current OWASP rule set straight from the OWASP website.

Nothing about the OWASP categories is hardcoded here beyond the entry URL: the
category list, the wording of each risk, the prevention guidance and the mapped
CWE numbers are all pulled from the live pages. That matters because the Top 10
is re-published every few years and categories get renamed and reordered -- a
scan graded against a stale copy of the list reports the wrong category names.

Outputs two files in --out-dir:

  owasp-taxonomy.json          machine-readable, consumed by scan_repos.py and
                               render_report.py (includes a CWE -> category index)
  owasp-taxonomy-<stamp>.md    human-readable snapshot, kept as run evidence

A JSON summary is printed to stdout so the caller can see what was fetched and
what failed. Exit status is 0 when at least the category list was retrieved.

Usage:
  python fetch_owasp_taxonomy.py --out-dir ./.owasp-workspace
  python fetch_owasp_taxonomy.py --out-dir ./out --url https://owasp.org/page --merge standards.json
"""

from __future__ import annotations

import argparse
import html as html_module
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

USER_AGENT = "owasp-security-skill (+https://github.com/OWASP)"
TOP10_INDEX = "https://top10.owasp.org/2025/"

# The Top 10 category pages expose these H2 sections. Headings are matched
# case-insensitively with a trailing period tolerated, so a cosmetic edit on the
# OWASP side degrades one field instead of breaking the whole fetch.
SECTION_ALIASES = {
    "background": ("background",),
    "description": ("description",),
    "prevention": ("how to prevent",),
    "scenarios": ("example attack scenarios",),
    "references": ("references",),
    "cwes": ("list of mapped cwes", "list of mapped cwe"),
}


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")


def fetch(url: str, timeout: int) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset, "replace")


def strip_tags(fragment: str) -> str:
    """Turn an HTML fragment into readable plain text, keeping list structure."""
    text = re.sub(r"<(script|style|svg)\b.*?</\1>", " ", fragment, flags=re.S | re.I)
    text = re.sub(r"<li\b[^>]*>", "\n- ", text, flags=re.I)
    text = re.sub(r"<(br|/p|/div|/tr|/h[1-6]|/li|/table)\b[^>]*>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html_module.unescape(text)
    lines = [re.sub(r"[ \t ]+", " ", line).strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def split_sections(page: str) -> dict:
    """Map normalized H2/H3 heading text -> section body text.

    Table-of-contents links repeat the heading wording, so when a heading occurs
    more than once the longest body wins -- that one is the real section.
    """
    chunks = re.split(r"<h([23])\b[^>]*>(.*?)</h\1>", page, flags=re.S | re.I)
    sections: dict = {}
    for index in range(1, len(chunks) - 2, 3):
        heading = strip_tags(chunks[index + 1]).strip().lower().rstrip(".")
        body = strip_tags(chunks[index + 2])
        if len(body) > len(sections.get(heading, "")):
            sections[heading] = body
    return sections


def pick_section(sections: dict, key: str) -> str:
    for alias in SECTION_ALIASES[key]:
        if alias in sections:
            return sections[alias]
    return ""


def as_bullets(text: str) -> list:
    bullets = [line.lstrip("- ").strip() for line in text.splitlines() if line.startswith("- ")]
    if bullets:
        return bullets
    # Some sections are prose rather than a list; keep whole sentences as items.
    return [part.strip() for part in re.split(r"(?<=\.)\s+", text) if len(part.strip()) > 30]


def parse_index(page: str, base_url: str) -> list:
    """Pull the category rank / name / url triples out of the Top 10 index page."""
    found: dict = {}
    for href, label in re.findall(r"<a\b[^>]*href=\"([^\"]+)\"[^>]*>(.*?)</a>", page, re.S | re.I):
        text = strip_tags(label).strip()
        match = re.match(r"^(A\d{2})[:\s]*(\d{4})?\s*[-–]?\s*(.+)$", text)
        if not match or not re.search(r"A\d{2}", href):
            continue
        rank = match.group(1)
        name = match.group(3).strip()
        entry = found.setdefault(
            rank, {"rank": rank, "name": name, "url": urllib.parse.urljoin(base_url, href)}
        )
        # Prefer the longer label, e.g. "A05:2025 - Injection" over "A05 Injection".
        if len(name) > len(entry["name"]):
            entry["name"] = name
    return [found[key] for key in sorted(found)]


def blank_category(entry: dict) -> dict:
    return {
        "id": entry["rank"],
        "rank": entry["rank"],
        "name": entry["name"],
        "title": entry["rank"] + " " + entry["name"],
        "url": entry["url"],
        "background": "",
        "description": "",
        "prevention": [],
        "references": [],
        "cwes": [],
    }


def parse_category(page: str, entry: dict) -> dict:
    sections = split_sections(page)
    cwes = []
    seen = set()
    for number, title in re.findall(r"CWE-(\d+)\s+([^\n]+)", pick_section(sections, "cwes")):
        if number in seen:
            continue
        seen.add(number)
        cwes.append({"cwe": "CWE-" + number, "title": title.strip()})

    heading = re.search(r"<h1\b[^>]*>(.*?)</h1>", page, re.S | re.I)
    title = strip_tags(heading.group(1)).strip() if heading else ""
    year = re.search(r"A\d{2}:(\d{4})", title) or re.search(r"_(\d{4})-", entry["url"])

    category = blank_category(entry)
    category.update(
        {
            "id": entry["rank"] + ":" + year.group(1) if year else entry["rank"],
            "title": title or category["title"],
            "background": pick_section(sections, "background"),
            "description": pick_section(sections, "description"),
            "prevention": as_bullets(pick_section(sections, "prevention")),
            "references": as_bullets(pick_section(sections, "references"))[:20],
            "cwes": cwes,
        }
    )
    return category


def build_cwe_index(categories: list) -> dict:
    """CWE -> the OWASP categories that claim it, so findings can self-classify."""
    index: dict = {}
    for category in categories:
        for item in category["cwes"]:
            index.setdefault(item["cwe"], []).append(category["id"])
    return index


def render_markdown(taxonomy: dict) -> str:
    lines = [
        "# OWASP taxonomy snapshot",
        "",
        "- Fetched at: `" + taxonomy["fetched_at"] + "`",
        "- Primary source: " + taxonomy["sources"]["top10_index"],
        "- Categories: " + str(len(taxonomy["categories"])),
        "- Distinct CWEs mapped: " + str(len(taxonomy["cwe_index"])),
        "",
        "This file is a point-in-time copy of the guidance a scan was graded against.",
        "Re-run `fetch_owasp_taxonomy.py` rather than editing it by hand.",
        "",
        "## Categories",
        "",
    ]
    for category in taxonomy["categories"]:
        lines += ["### " + category["id"] + " - " + category["name"], "", "Source: " + category["url"], ""]
        if category["description"]:
            lines += [category["description"][:1500].strip(), ""]
        if category["prevention"]:
            lines += ["**How to prevent**", ""]
            lines += ["- " + item for item in category["prevention"]]
            lines.append("")
        if category["cwes"]:
            lines += ["**Mapped CWEs (" + str(len(category["cwes"])) + ")**", ""]
            lines += ["- " + item["cwe"] + " " + item["title"] for item in category["cwes"]]
            lines.append("")

    standards = taxonomy.get("standards") or []
    if standards:
        lines += ["## OWASP standards and supporting projects", ""]
        for standard in standards:
            lines += ["### " + standard.get("name", "(unnamed)"), ""]
            if standard.get("url"):
                lines += ["Source: " + standard["url"], ""]
            if standard.get("summary"):
                lines += [standard["summary"].strip(), ""]
            for check in standard.get("checks") or []:
                lines.append("- " + check)
            lines.append("")

    failures = taxonomy.get("failures") or []
    if failures:
        lines += ["## Sources that could not be read", ""]
        lines += ["- " + failure["url"] + ": " + failure["error"] for failure in failures]
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--out-dir", required=True, help="where to write the taxonomy JSON and Markdown")
    parser.add_argument(
        "--top10-index", default=TOP10_INDEX, help="Top 10 index URL (default: " + TOP10_INDEX + ")"
    )
    parser.add_argument(
        "--url",
        action="append",
        default=[],
        metavar="URL",
        help="additional static OWASP page to capture as plain text; repeatable",
    )
    parser.add_argument(
        "--merge",
        metavar="JSON",
        help="JSON file with a 'standards' list to merge in, for pages this script cannot read "
        "server-side (owasp.org/projects renders client-side, so gather those with the "
        "agent's own web tooling and pass them here)",
    )
    parser.add_argument("--timeout", type=int, default=30, help="per-request timeout in seconds (default: 30)")
    parser.add_argument(
        "--skip-category-pages",
        action="store_true",
        help="read only the index: faster, but no prevention guidance and no CWE mapping",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    failures: list = []

    try:
        index_page = fetch(args.top10_index, args.timeout)
    except Exception as error:  # noqa: BLE001 - transport failures are reported, not raised
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "could not read " + args.top10_index + ": " + str(error),
                    "hint": "fall back to the agent's own web fetch tool for the OWASP pages",
                },
                indent=2,
            )
        )
        return 1

    entries = parse_index(index_page, args.top10_index)
    if not entries:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "no categories found on the index page",
                    "hint": "the page layout may have changed; read it with the agent's web fetch tool",
                },
                indent=2,
            )
        )
        return 1

    categories = []
    for entry in entries:
        if args.skip_category_pages:
            categories.append(blank_category(entry))
            continue
        try:
            categories.append(parse_category(fetch(entry["url"], args.timeout), entry))
        except Exception as error:  # noqa: BLE001
            failures.append({"url": entry["url"], "error": str(error)})
            categories.append(blank_category(entry))

    extra_pages = []
    for url in args.url:
        try:
            extra_pages.append({"url": url, "text": strip_tags(fetch(url, args.timeout))[:20000]})
        except Exception as error:  # noqa: BLE001
            failures.append({"url": url, "error": str(error)})

    standards = []
    if args.merge:
        merged = json.loads(Path(args.merge).read_text(encoding="utf-8"))
        standards = merged.get("standards", []) if isinstance(merged, dict) else merged

    taxonomy = {
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": {"top10_index": args.top10_index, "extra_urls": args.url},
        "categories": categories,
        "cwe_index": build_cwe_index(categories),
        "standards": standards,
        "extra_pages": extra_pages,
        "failures": failures,
    }

    json_path = out_dir / "owasp-taxonomy.json"
    md_path = out_dir / ("owasp-taxonomy-" + utc_stamp() + ".md")
    json_path.write_text(json.dumps(taxonomy, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(taxonomy), encoding="utf-8")

    print(
        json.dumps(
            {
                "ok": True,
                "taxonomy_json": str(json_path),
                "taxonomy_markdown": str(md_path),
                "categories": [c["id"] + " " + c["name"] for c in categories],
                "cwes_mapped": len(taxonomy["cwe_index"]),
                "standards_merged": len(standards),
                "failures": failures,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
