#!/usr/bin/env python3
"""
Generate FLARE branding BMP images for Inno Setup.

  banner.bmp      164 x 314  (left sidebar on welcome / finish pages)
  small.bmp        55 x  55  (top-right corner on every other page)

Palette and logo are matched to the FLARE web dashboard (server/ui/index.html):
navy gradient background, teal accents, an orange flame mark and the FLARE
wordmark in orange, with the "by IU · Beaconers" sub-brand.

Uses Pillow if available, otherwise writes a minimal solid-colour BMP
so the build never hard-fails on a machine without Pillow.
"""

import struct
import sys
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# FLARE dashboard palette  (RGB tuples) — see :root in server/ui/index.html
NAVY    = ( 10,  14,  39)   # #0A0E27  --bg
NAVY2   = ( 26,  31,  58)   # #1A1F3A  --bg2
TEAL    = ( 78, 205, 196)   # #4ECDC4  --teal
ORANGE  = (255, 107,  53)   # #FF6B35  --orange (brand / logo)
TEXT    = (224, 230, 237)   # #E0E6ED  --text
MUTED   = (136, 146, 166)   # #8892A6  --text2

# back-compat aliases used by the solid-colour fallback
DARK    = NAVY


# ─────────────────────────────────────────────────────────────────────────────
# Minimal BMP writer  (no dependencies)
# ─────────────────────────────────────────────────────────────────────────────

def _write_bmp_solid(path: str, width: int, height: int, rgb: tuple):
    """Write a solid-colour 24-bit BMP (bottom-up, no compression)."""
    row_bytes = width * 3
    pad       = (4 - row_bytes % 4) % 4
    stride    = row_bytes + pad
    pixel_off = 14 + 40
    file_size = pixel_off + stride * height

    with open(path, "wb") as f:
        # File header
        f.write(b"BM")
        f.write(struct.pack("<I", file_size))
        f.write(struct.pack("<HH", 0, 0))
        f.write(struct.pack("<I", pixel_off))
        # Info header (BITMAPINFOHEADER)
        f.write(struct.pack("<I", 40))
        f.write(struct.pack("<i", width))
        f.write(struct.pack("<i", height))   # positive = bottom-up
        f.write(struct.pack("<H", 1))        # planes
        f.write(struct.pack("<H", 24))       # bits per pixel
        f.write(struct.pack("<I", 0))        # no compression
        f.write(struct.pack("<I", stride * height))
        f.write(struct.pack("<iillI", 2835, 2835, 0, 0, 0))
        # Pixel data (BGR order, bottom row first)
        row = bytes([rgb[2], rgb[1], rgb[0]] * width) + b"\x00" * pad
        for _ in range(height):
            f.write(row)


# ─────────────────────────────────────────────────────────────────────────────
# Rich version  (Pillow)
# ─────────────────────────────────────────────────────────────────────────────

def _load_font(size: int, bold: bool):
    from PIL import ImageFont
    faces = (["segoeuib.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf"] if bold
             else ["segoeui.ttf", "arial.ttf", "DejaVuSans.ttf"])
    for face in faces:
        try:
            return ImageFont.truetype(face, size)
        except Exception:
            continue
    return ImageFont.load_default()


def _vgradient(draw, w, top_y, bottom_y, c_top, c_bot):
    """Vertical gradient between two RGB colours (matches the dashboard's
    135deg --bg -> --bg2 fill, simplified to vertical for the narrow banner)."""
    span = max(1, bottom_y - top_y)
    for y in range(top_y, bottom_y):
        t = (y - top_y) / span
        draw.line([(0, y), (w, y)], fill=tuple(
            int(c_top[i] + (c_bot[i] - c_top[i]) * t) for i in range(3)))


def _flame(draw, cx, cy, scale, glow=True):
    """Draw a stylised flame: orange outer body with a teal-tinted inner core,
    echoing the dashboard's orange logo + teal accent pairing."""
    s = scale
    outer = [
        (cx,            cy - 1.9 * s),
        (cx + 0.95 * s, cy - 0.4 * s),
        (cx + 1.15 * s, cy + 0.7 * s),
        (cx + 0.55 * s, cy + 1.6 * s),
        (cx - 0.55 * s, cy + 1.6 * s),
        (cx - 1.15 * s, cy + 0.7 * s),
        (cx - 0.95 * s, cy - 0.4 * s),
    ]
    if glow:
        # soft orange halo
        draw.ellipse([cx - 1.7 * s, cy - 2.1 * s, cx + 1.7 * s, cy + 2.0 * s],
                     fill=(NAVY2[0] + 20, NAVY2[1] + 14, NAVY2[2] + 8))
    draw.polygon(outer, fill=ORANGE)
    inner = [
        (cx,            cy - 0.9 * s),
        (cx + 0.55 * s, cy + 0.3 * s),
        (cx + 0.30 * s, cy + 1.2 * s),
        (cx - 0.30 * s, cy + 1.2 * s),
        (cx - 0.55 * s, cy + 0.3 * s),
    ]
    draw.polygon(inner, fill=TEAL)


def _text_spaced(draw, cx, y, text, font, fill, spacing):
    """Centre `text` at x=cx with extra letter spacing (PIL has none built in)."""
    widths = [draw.textlength(ch, font=font) for ch in text]
    total  = sum(widths) + spacing * (len(text) - 1)
    x = cx - total / 2
    for ch, w in zip(text, widths):
        draw.text((x, y), ch, font=font, fill=fill)
        x += w + spacing


# Supplied brand asset: a flame icon on a navy background (no wordmark).
LOGO_FILE = os.path.join(OUT_DIR, "flare_logo.png")


def _fit(img, max_w, max_h):
    """Scale img to fit within (max_w, max_h), preserving aspect ratio."""
    from PIL import Image
    w, h = img.size
    s = min(max_w / w, max_h / h)
    return img.resize((max(1, round(w * s)), max(1, round(h * s))), Image.LANCZOS)


# Warmth threshold (R-B) at which a flame pixel becomes fully opaque when the
# navy backdrop is keyed out. The supplied asset is a warm orange/yellow flame
# on a flat navy box with a faint grey glow; keying on warmth (R-B) rather than
# colour distance removes both the navy box *and* the grey glow cleanly, leaving
# only the flame so it can be alpha-composited onto any background with no seam.
_FLAME_WARM_T = 45.0


def _keyed_flame(logo):
    """Return an RGBA copy of the flame asset with its navy background removed.

    Pixel alpha is derived from warmth (red minus blue): saturated flame pixels
    stay opaque, the near-grey navy box and glow fade to transparent."""
    from PIL import Image
    rgb = logo.convert("RGB")
    w, h = rgb.size
    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    sp, op = rgb.load(), out.load()
    for y in range(h):
        for x in range(w):
            r, g, b = sp[x, y]
            a = max(0.0, min(1.0, (r - b) / _FLAME_WARM_T))
            op[x, y] = (r, g, b, int(round(a * 255)))
    return out


def _try_pillow(banner_path: str, small_path: str) -> bool:
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return False

    big   = _load_font(34, bold=True)
    small = _load_font(11, bold=False)
    micro = _load_font(10, bold=True)

    logo = None
    if os.path.exists(LOGO_FILE):
        try:
            logo = Image.open(LOGO_FILE).convert("RGB")
        except Exception:
            logo = None

    W, H = 164, 314

    if logo is not None:
        # Flame-only asset: centre it on the navy banner and draw the FLARE
        # wordmark beneath it. Match the banner fill to the asset's own
        # background so the paste has no visible seam.
        bg = logo.getpixel((0, 0))                      # ~navy from the asset
        img  = Image.new("RGB", (W, H), bg)
        draw = ImageDraw.Draw(img)
        _vgradient(draw, W, 150, H, bg, NAVY2)

        # Flame centred near the top. Key out the asset's navy box first and
        # paste with its own alpha as the mask so the flame blends seamlessly
        # into the gradient instead of sitting in a visible rectangle.
        flame = _fit(_keyed_flame(logo), 96, 104)
        fx = (W - flame.size[0]) // 2
        fy = 30
        img.paste(flame, (fx, fy), flame)

        # FLARE wordmark below the flame (dashboard orange, letter-spaced).
        word_y = fy + flame.size[1] + 10
        _text_spaced(draw, W // 2, word_y, "FLARE", big, ORANGE, 4)

        # divider + tagline
        below = word_y + 46
        draw.line([(24, below), (W - 24, below)], fill=TEAL, width=1)
        for i, line in enumerate(["Endpoint · Network", "Threat Detection",
                                  "Federated ML"]):
            _text_spaced(draw, W // 2, below + 14 + i * 18, line, small, MUTED, 0)

        # sub-brand (dashboard .logo-sub)
        _text_spaced(draw, W // 2, 286, "by IU · Beaconers", micro, TEAL, 1)

        img.save(banner_path, "BMP")

        # ── Small 55x55: the flame, scaled to fit, centred on navy ────────────
        S = 55
        simg = Image.new("RGB", (S, S), bg)
        sflame = _fit(_keyed_flame(logo), S - 6, S - 6)
        simg.paste(sflame, ((S - sflame.size[0]) // 2, (S - sflame.size[1]) // 2), sflame)
        simg.save(small_path, "BMP")
        return True

    # ── Fallback: no logo file — draw a flame from scratch ───────────────────
    big = _load_font(34, bold=True)
    img  = Image.new("RGB", (W, H), NAVY)
    draw = ImageDraw.Draw(img)
    _vgradient(draw, W, 0, H, NAVY, NAVY2)
    _flame(draw, W // 2, 86, 22)
    _text_spaced(draw, W // 2, 138, "FLARE", big, ORANGE, 4)
    draw.line([(24, 182), (W - 24, 182)], fill=TEAL, width=1)
    for i, line in enumerate(["Endpoint · Network", "Threat Detection",
                              "Federated ML"]):
        _text_spaced(draw, W // 2, 196 + i * 18, line, small, MUTED, 0)
    _text_spaced(draw, W // 2, 286, "by IU · Beaconers", micro, TEAL, 1)
    img.save(banner_path, "BMP")

    S = 55
    img = Image.new("RGB", (S, S), NAVY)
    draw = ImageDraw.Draw(img)
    _vgradient(draw, S, 0, S, NAVY, NAVY2)
    _flame(draw, S // 2, S // 2 - 2, 12)
    img.save(small_path, "BMP")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def _emit_transparent_logo():
    """Write a background-removed copy of the flame asset for the web dashboard.

    Saved both next to the installer assets (flare_logo_transparent.png) and into
    server/ui/flare_logo.png so the dashboard can show the flame on its navy
    background with no surrounding box."""
    try:
        from PIL import Image
    except ImportError:
        return
    if not os.path.exists(LOGO_FILE):
        return
    keyed = _keyed_flame(Image.open(LOGO_FILE))
    keyed.save(os.path.join(OUT_DIR, "flare_logo_transparent.png"))
    ui_logo = os.path.normpath(
        os.path.join(OUT_DIR, "..", "server", "ui", "flare_logo.png"))
    try:
        keyed.save(ui_logo)
        print(f"        {ui_logo}")
    except Exception:
        pass


def main():
    banner = os.path.join(OUT_DIR, "banner.bmp")
    small  = os.path.join(OUT_DIR, "small.bmp")

    if _try_pillow(banner, small):
        print(f"  [OK]  Created rich images using Pillow")
    else:
        _write_bmp_solid(banner, 164, 314, NAVY)
        _write_bmp_solid(small,   55,  55, NAVY)
        print("  [OK]  Created solid-colour images (install Pillow for logo/text)")

    _emit_transparent_logo()

    print(f"        {banner}")
    print(f"        {small}")


if __name__ == "__main__":
    main()
