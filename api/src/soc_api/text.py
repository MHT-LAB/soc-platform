"""Handling of text that came from an alert, which an attacker may have written.

Two jobs, shared by the pager worker (what crosses the push server) and the console
(what is shown to an analyst):

* clean(): plain, single-line text for a push or a title.
* visible(): text for a person to read, in which anything that could hide or reorder
  content (control characters, bidi overrides, zero-width marks) is made visible as
  ⟦U+XXXX⟧ instead of being dropped or obeyed.
* safe_link(): a click target only if it is the vendor's https console and nothing but
  URL characters.
"""

import re
import unicodedata

LC_LINK_PREFIX = "https://app.limacharlie.io/"


def clean(text: str | None, limit: int) -> str:
    """Plain, single-line text: control and format characters dropped (this includes
    newlines turned into spaces first), runs of white space collapsed, then cut."""
    out = []
    for ch in text or "":
        category = unicodedata.category(ch)
        if category[0] == "Z" or ch in "\t\n\r\x0b\x0c":
            out.append(" ")
        elif category[0] != "C":
            out.append(ch)
    return " ".join("".join(out).split())[:limit]


def visible(text: str | None, limit: int | None = None) -> str:
    """Text to show a person. Newlines and tabs stay; every other control, format,
    surrogate or unassigned character becomes ⟦U+XXXX⟧. Cut at `limit` characters of
    the input."""
    out = []
    for ch in (text or "")[:limit]:
        if ch not in "\n\t" and unicodedata.category(ch)[0] == "C":
            out.append(f"⟦U+{ord(ch):04X}⟧")
        else:
            out.append(ch)
    return "".join(out)


# The characters of a URL (RFC 3986) minus the ones that open or close markup, quoting or
# escapes: no quote, apostrophe, angle bracket, backslash, backtick, brace, bar or caret.
_URL_CHARS = re.compile(r"[A-Za-z0-9\-._~:/?#\[\]@!$&()*+,;=%]+")


def safe_link(link: str | None) -> str | None:
    """A click target only if it is the vendor's https console and nothing but URL
    characters."""
    if link and len(link) <= 512 and link.startswith(LC_LINK_PREFIX) and _URL_CHARS.fullmatch(link):
        return link
    return None


def link_path(link: str | None) -> str | None:
    """What follows the vendor's console address in a safe link, for templates that write
    the address itself; None when the link is not safe."""
    ok = safe_link(link)
    return None if ok is None else ok[len(LC_LINK_PREFIX) :]
