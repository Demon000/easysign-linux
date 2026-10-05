"""The single source of truth for how the signature looks. The same style and
params feed both the on-page stamps/signature and the GUI preview, so they match."""
import datetime
import io

WHEN_FORMAT = "%Y.%m.%d %H:%M:%S"


def now_when():
    return datetime.datetime.now().strftime(WHEN_FORMAT)


def default_template(country=None):
    """Adobe/EasySign-style block. Uses the custom %(when)s token (not pyHanko's
    reserved %(ts)s) so we control the timestamp identically everywhere."""
    lines = ["Digitally signed by", "%(signer)s"]
    if country:
        lines.append("%(country)s")
    lines.append("%(when)s")
    return "\n".join(lines)


def make_style(template, font_size=10, border_width=1):
    from pyhanko.pdf_utils.text import TextBoxStyle
    from pyhanko.stamp import TextStampStyle

    return TextStampStyle(
        stamp_text=template,
        text_box_style=TextBoxStyle(font_size=font_size),
        border_width=border_width,
    )


def auto_font_size(width_pt, height_pt, template, params):
    """Largest font that fits the rendered text in a box of the given size, so the
    appearance scales with the box instead of needing a fixed minimum box."""
    try:
        text = template % params
    except Exception:
        text = template
    lines = text.split("\n") or [""]
    nlines = len(lines)
    maxchars = max((len(ln) for ln in lines), default=1) or 1
    fit_height = height_pt / (nlines * 1.55)
    fit_width = width_pt / (maxchars * 0.65)  # Courier advance ~0.6 em
    # int: pyHanko's text layout does Fraction(w, h) and rejects float metrics.
    return max(4, int(min(fit_height, fit_width, 40.0)))


def make_params(signer, when, country=None):
    params = {"signer": signer, "when": when}
    if country:
        params["country"] = country
    return params


def render_preview(style, params, width_pt, height_pt, zoom=2.0):
    """Render the stamp exactly as pyHanko would, as PNG bytes, for the GUI."""
    import pymupdf
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils.layout import BoxConstraints
    from pyhanko.stamp import TextStamp

    iw, ih = int(round(width_pt)), int(round(height_pt))
    doc = pymupdf.open()
    page = doc.new_page(width=iw, height=ih)
    page.draw_rect(page.rect, fill=(1, 1, 1), color=(1, 1, 1))  # force /Contents
    buf = io.BytesIO()
    doc.save(buf)
    doc.close()
    buf.seek(0)

    w = IncrementalPdfFileWriter(buf)
    box = BoxConstraints(width=iw, height=ih)  # pyHanko needs int dims
    TextStamp(w, style, text_params=params, box=box).apply(0, 0, 0)
    out = io.BytesIO()
    w.write(out)

    rendered = pymupdf.open(stream=out.getvalue(), filetype="pdf")
    png = rendered[0].get_pixmap(matrix=pymupdf.Matrix(zoom, zoom)).tobytes("png")
    rendered.close()
    return png
