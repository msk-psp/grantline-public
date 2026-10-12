"""One local SVG identifies the console, login screen and browser tab."""
import xml.etree.ElementTree as ET
from pathlib import Path

from grantline.pages import _nav, _shell, render_login

icon = Path(__file__).resolve().parents[1] / "grantline/static/grantline-icon.svg"
svg = ET.fromstring(icon.read_text())
assert svg.attrib["viewBox"] == "0 0 64 64"
assert not any(el.tag.endswith("script") for el in svg.iter())
assert not any("href" in key for el in svg.iter() for key in el.attrib)
for markup in (_nav("/"), render_login(None)):
    assert 'grantline-icon.svg?v=' in markup
    assert 'width="28" height="28" alt=""' in markup
    assert '>Grantline</a>' in markup
assert '<link rel="icon" type="image/svg+xml"' in _shell("Example")
