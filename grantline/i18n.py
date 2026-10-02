"""Console translations. Translate templates before inserting service data."""
from __future__ import annotations

import html
import json
import re
from contextvars import ContextVar
from functools import lru_cache
from http.cookies import CookieError, SimpleCookie
from pathlib import Path

LANGUAGES = {"en": "English", "ko": "한국어", "ja": "日本語", "zh-CN": "简体中文"}
language = ContextVar("console_language", default="en")


def supported(value: str) -> str:
    value = value.lower().replace("_", "-")
    if value.startswith("zh"):
        return "zh-CN"
    return value.split("-", 1)[0] if value.split("-", 1)[0] in LANGUAGES else ""


def negotiate(explicit: str, cookie: str, accept: str) -> str:
    if explicit in LANGUAGES:
        return explicit
    jar = SimpleCookie()
    try:
        jar.load(cookie)
    except CookieError:  # malformed cookies must not break a console page
        pass
    saved = jar.get("grantline_lang")
    if saved and saved.value in LANGUAGES:
        return saved.value
    choices = []
    for item in accept.split(","):
        name, _, params = item.strip().partition(";")
        try:
            quality = float(params.strip().removeprefix("q=")) if params else 1.0
        except ValueError:
            continue
        if 0 < quality <= 1 and supported(name):
            choices.append((quality, supported(name)))
    return max(choices, key=lambda pair: pair[0])[1] if choices else "en"


@lru_cache(maxsize=4)
def catalog(lang: str) -> dict[str, str]:
    if lang == "en":
        return {}
    return json.loads((Path(__file__).parent / "locales" / f"{lang}.json").read_text(encoding="utf-8"))


def t(message: str, *values) -> str:
    key = " ".join(html.unescape(message).split())
    translated = catalog(language.get()).get(key, message)
    return translated.format(*values) if values else translated


@lru_cache(maxsize=2048)
def _template(template: str, lang: str) -> str:
    """Only developer-owned text/labels are translated; placeholders stay opaque."""
    if lang == "en":
        return template
    translations = catalog(lang)
    out, protected = [], False
    for part in re.split(r"(<[^>]*>)", template):
        if part.startswith("<"):
            if re.match(r"<\s*(code|pre|script|style)\b", part):
                protected = True
            elif re.match(r"</\s*(code|pre|script|style)\b", part):
                protected = False
            part = re.sub(r'(title|aria-label|placeholder)="([^"]*)"',
                          lambda m: f'{m[1]}="{html.escape(translations.get(" ".join(html.unescape(m[2]).split()), html.unescape(m[2])), quote=True)}"', part)
        elif not protected:
            key = " ".join(html.unescape(part).split())
            if key in translations:
                leading = part[:len(part) - len(part.lstrip())]
                trailing = part[len(part.rstrip()):]
                part = leading + html.escape(translations[key], quote=False) + trailing
        out.append(part)
    return "".join(out)


def h(template: str, *values) -> str:
    return _template(template, language.get()).format(*values)


def client_catalog() -> str:
    # This is a JSON data block, not executable JavaScript; never let '<' end its tag.
    return json.dumps(catalog(language.get()), ensure_ascii=False).replace("<", "\\u003c")


def elapsed(message: str) -> str:
    match = re.fullmatch(r"(\d+) (minutes?|hours?|days?|months?) ago", message)
    return t("{0} " + match[2] + " ago", match[1]) if match else t(message)
