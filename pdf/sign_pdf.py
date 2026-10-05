#!/usr/bin/env python3
"""Sign a PDF (PAdES) with a Trans Sped cloud certificate via the easysign PKCS#11
module. Signing triggers the easysign agent's credential window (password + OTP).

The rich multi-page, multi-placement workflow lives in the GUI (easysign-sign-gui);
this CLI covers headless / single-placement signing."""
import argparse
import sys

from easysign_sign import agent, signer

ANCHORS = {"bottom-right", "bottom-left", "top-right", "top-left"}


def choose_cert(explicit):
    entries = agent.list_entries()
    if not entries:
        sys.exit("no certificates (easysign profile add <phone>)")
    if explicit:
        for e in entries:
            if explicit in (e["label"], e["credential_id"]):
                return e
        sys.exit(f"no certificate matching {explicit!r}")
    if len(entries) == 1:
        return entries[0]
    print("Select a certificate:")
    for i, e in enumerate(entries, 1):
        print(f"  {i}) {e['label']}")
    while True:
        choice = input(f"Which? [1-{len(entries)}] ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(entries):
            return entries[int(choice) - 1]


def page_size(path, page):
    import pymupdf

    with pymupdf.open(path) as doc:
        r = doc[page].rect
        return r.width, r.height


def box_from_anchor(path, page, anchor, size, margin):
    w, h = page_size(path, page)
    bw, bh = size
    if anchor == "bottom-right":
        x1, y1 = w - margin - bw, margin
    elif anchor == "bottom-left":
        x1, y1 = margin, margin
    elif anchor == "top-right":
        x1, y1 = w - margin - bw, h - margin - bh
    else:
        x1, y1 = margin, h - margin - bh
    return (x1, y1, x1 + bw, y1 + bh)


def box_from_pick(path, page):
    import tkinter as tk

    import pymupdf

    with pymupdf.open(path) as doc:
        pg = doc[page]
        pw, ph = pg.rect.width, pg.rect.height
        zoom = min(1200.0 / pw, 1500.0 / ph, 2.0)
        pix = pg.get_pixmap(matrix=pymupdf.Matrix(zoom, zoom))
        png = pix.tobytes("ppm")

    root = tk.Tk()
    root.title("easysign — drag the signature box, then release")
    img = tk.PhotoImage(data=png)
    canvas = tk.Canvas(root, width=img.width(), height=img.height())
    canvas.pack()
    canvas.create_image(0, 0, anchor="nw", image=img)
    st = {"x0": 0, "y0": 0, "rect": None, "box": None}

    def down(e):
        st["x0"], st["y0"] = e.x, e.y
        if st["rect"]:
            canvas.delete(st["rect"])
        st["rect"] = canvas.create_rectangle(e.x, e.y, e.x, e.y, outline="red", width=2)

    def drag(e):
        canvas.coords(st["rect"], st["x0"], st["y0"], e.x, e.y)

    def up(e):
        x1, x2 = sorted((st["x0"], e.x))
        y1, y2 = sorted((st["y0"], e.y))
        sx, sy = pw / img.width(), ph / img.height()
        st["box"] = (x1 * sx, ph - y2 * sy, x2 * sx, ph - y1 * sy)
        root.after(120, root.destroy)

    canvas.bind("<ButtonPress-1>", down)
    canvas.bind("<B1-Motion>", drag)
    canvas.bind("<ButtonRelease-1>", up)
    root.mainloop()
    if not st["box"]:
        sys.exit("no box selected")
    return st["box"]


def parse_stamp(spec):
    page_s, box_s = spec.split(":", 1)
    box = tuple(float(v) for v in box_s.split(","))
    return {"role": "visual", "page": int(page_s) - 1, "box": box}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", nargs="?")
    ap.add_argument("output", nargs="?")
    ap.add_argument("--list", action="store_true", help="list certificates and exit")
    ap.add_argument("--cert", help="certificate label (default: the only one, or pick)")
    ap.add_argument("--visible", action="store_true", help="visible signature box")
    ap.add_argument("--page", type=int, default=1, help="1-based page for the signature")
    ap.add_argument("--box", help="x1,y1,x2,y2 PDF pts (bottom-left origin)")
    ap.add_argument("--anchor", choices=sorted(ANCHORS))
    ap.add_argument("--size", default="200x60", help="WxH for --anchor")
    ap.add_argument("--margin", type=float, default=36.0)
    ap.add_argument("--pick", action="store_true", help="drag the box on a preview")
    ap.add_argument(
        "--stamp",
        action="append",
        default=[],
        metavar="PAGE:x1,y1,x2,y2",
        help="extra visual appearance (repeatable); 1-based page",
    )
    ap.add_argument("--reason")
    ap.add_argument("--location")
    ap.add_argument("--template", help="override the appearance text template")
    args = ap.parse_args()

    if args.list:
        for e in agent.list_entries():
            print(e["label"])
        return
    if not args.input or not args.output:
        ap.error("input and output are required")

    cert = choose_cert(args.cert)
    page0 = args.page - 1

    box = None
    if args.visible:
        if args.pick:
            box = box_from_pick(args.input, page0)
        elif args.box:
            box = tuple(float(v) for v in args.box.split(","))
        elif args.anchor:
            w, h = (float(v) for v in args.size.lower().split("x"))
            box = box_from_anchor(args.input, page0, args.anchor, (w, h), args.margin)
        else:
            ap.error("--visible needs one of --box, --anchor, or --pick")

    placements = [{"role": "signature", "page": page0, "box": box}]
    placements += [parse_stamp(s) for s in args.stamp]

    signer.sign(
        args.input,
        args.output,
        cert["credential_id"],
        cert["der"],
        placements,
        reason=args.reason,
        location=args.location,
        template=args.template,
    )
    print(f"signed -> {args.output}")


if __name__ == "__main__":
    main()
