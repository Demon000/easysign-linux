#!/usr/bin/env python3
"""easysign PDF signing GUI. Open a PDF, pick a certificate, place your signature
appearance on one or more pages (live rendered preview), then produce one PAdES-signed
PDF (one OTP via the easysign agent). One placement is the real digital signature; any
others are visual copies of the same appearance, all covered by that one signature."""
import sys

from PySide6 import QtCore, QtGui, QtWidgets

from easysign_sign import agent, appearance

ZOOM = 1.6
PAGE_GAP = 16
BOX_COLOR = QtGui.QColor("#2d6cdf")
DEFAULT_BOX = QtCore.QSizeF(260, 80)  # scene px for a plain click
MIN_BOX = QtCore.QSizeF(40, 20)       # floor while resizing (font scales to fit)
CLICK_SLOP = 16                       # drag smaller than this = a click
GRIP = 14                             # bottom-right resize grip, scene px


class BoxItem(QtWidgets.QGraphicsRectItem):
    """A placed signature appearance, showing the live rendered preview. Movable;
    drag the bottom-right grip to resize."""

    def __init__(self, rect, order, window):
        super().__init__(rect)
        self.order = order
        self.window = window
        self._template = None
        self._params = None
        self._resizing = False
        self.setFlags(
            QtWidgets.QGraphicsItem.ItemIsMovable
            | QtWidgets.QGraphicsItem.ItemIsSelectable
        )
        self.setAcceptHoverEvents(True)
        self.setPen(QtGui.QPen(BOX_COLOR, 2))
        self.setBrush(QtGui.QColor(255, 255, 255, 230))
        self.pix = QtWidgets.QGraphicsPixmapItem(self)

    def render(self, template, params):
        self._template, self._params = template, params
        self._render_pixmap()

    def _render_pixmap(self):
        if self._template is None:
            return
        r = self.rect()
        w_pt = max(r.width() / ZOOM, 20)
        h_pt = max(r.height() / ZOOM, 12)
        fs = appearance.auto_font_size(w_pt, h_pt, self._template, self._params)
        style = appearance.make_style(self._template, font_size=fs)
        try:
            png = appearance.render_preview(
                style, self._params, w_pt, h_pt, zoom=ZOOM
            )
        except Exception:
            self.pix.setPixmap(QtGui.QPixmap())
            return
        pm = QtGui.QPixmap()
        pm.loadFromData(png)
        if not pm.isNull():
            self.pix.setPixmap(
                pm.scaled(
                    int(r.width()), int(r.height()),
                    QtCore.Qt.IgnoreAspectRatio, QtCore.Qt.SmoothTransformation,
                )
            )

    def _grip_rect(self):
        r = self.rect()
        return QtCore.QRectF(
            r.right() - GRIP, r.bottom() - GRIP, GRIP, GRIP
        )

    def paint(self, painter, option, widget=None):
        super().paint(painter, option, widget)
        g = self._grip_rect()
        painter.setBrush(BOX_COLOR)
        painter.setPen(QtGui.QPen(QtCore.Qt.white, 1))
        painter.drawRect(g)

    def hoverMoveEvent(self, ev):
        if self._grip_rect().contains(ev.pos()):
            self.setCursor(QtCore.Qt.SizeFDiagCursor)
        else:
            self.setCursor(QtCore.Qt.SizeAllCursor)
        super().hoverMoveEvent(ev)

    def mousePressEvent(self, ev):
        if self._grip_rect().contains(ev.pos()):
            self._resizing = True
            ev.accept()
            return
        super().mousePressEvent(ev)

    def mouseMoveEvent(self, ev):
        if self._resizing:
            r = self.rect()
            w = max(MIN_BOX.width(), ev.pos().x() - r.left())
            h = max(MIN_BOX.height(), ev.pos().y() - r.top())
            self.prepareGeometryChange()
            self.setRect(r.left(), r.top(), w, h)
            # cheap live scale; crisp re-render on release
            if not self.pix.pixmap().isNull():
                self.pix.setPixmap(
                    self.pix.pixmap().scaled(
                        int(w), int(h),
                        QtCore.Qt.IgnoreAspectRatio, QtCore.Qt.FastTransformation,
                    )
                )
            return
        super().mouseMoveEvent(ev)

    def mouseReleaseEvent(self, ev):
        if self._resizing:
            self._resizing = False
            self._render_pixmap()
            ev.accept()
            return
        super().mouseReleaseEvent(ev)


class PageView(QtWidgets.QGraphicsView):
    def __init__(self, window):
        super().__init__()
        self.window = window
        self.setScene(QtWidgets.QGraphicsScene(self))
        self.setRenderHint(QtGui.QPainter.Antialiasing)
        self.placing = False
        self._origin = None
        self._rubber = None
        self.pages = []

    def load(self, path):
        import pymupdf

        self.scene().clear()
        self.pages.clear()
        doc = pymupdf.open(path)
        y = 0.0
        for i in range(doc.page_count):
            pg = doc[i]
            pix = pg.get_pixmap(matrix=pymupdf.Matrix(ZOOM, ZOOM))
            img = QtGui.QImage(
                pix.samples, pix.width, pix.height, pix.stride,
                QtGui.QImage.Format_RGB888,
            ).copy()
            item = self.scene().addPixmap(QtGui.QPixmap.fromImage(img))
            item.setPos(0, y)
            item.setZValue(-1)
            self.pages.append(
                {"top": y, "pt_w": pg.rect.width, "pt_h": pg.rect.height,
                 "pix_h": pix.height}
            )
            y += pix.height + PAGE_GAP
        doc.close()
        self.setSceneRect(self.scene().itemsBoundingRect())

    def start_place(self):
        self.placing = True
        self.viewport().setCursor(QtCore.Qt.CrossCursor)
        self.window.status.showMessage(
            "Click or drag on a page to place your signature"
        )

    def _disarm(self):
        self.placing = False
        self.viewport().unsetCursor()
        self.window.sync_mode_button()

    def mousePressEvent(self, ev):
        if self.placing and ev.button() == QtCore.Qt.LeftButton:
            self._origin = self.mapToScene(ev.position().toPoint())
            self._rubber = self.scene().addRect(
                QtCore.QRectF(self._origin, self._origin),
                QtGui.QPen(QtCore.Qt.DashLine),
            )
            return
        super().mousePressEvent(ev)

    def mouseMoveEvent(self, ev):
        if self._rubber is not None:
            cur = self.mapToScene(ev.position().toPoint())
            self._rubber.setRect(QtCore.QRectF(self._origin, cur).normalized())
            return
        super().mouseMoveEvent(ev)

    def mouseReleaseEvent(self, ev):
        if self._rubber is not None:
            rect = self._rubber.rect()
            self.scene().removeItem(self._rubber)
            self._rubber = None
            self._disarm()
            if rect.width() < CLICK_SLOP and rect.height() < CLICK_SLOP:
                rect = QtCore.QRectF(rect.topLeft(), DEFAULT_BOX)
            self.window.add_box(rect)
            return
        super().mouseReleaseEvent(ev)

    def keyPressEvent(self, ev):
        if ev.key() in (QtCore.Qt.Key_Delete, QtCore.Qt.Key_Backspace):
            for it in self.scene().selectedItems():
                if isinstance(it, BoxItem):
                    self.scene().removeItem(it)
            self.window.update_sign_enabled()
            return
        super().keyPressEvent(ev)

    def placement_for(self, item):
        r = item.mapRectToScene(item.rect())
        page = self.pages[-1]
        pidx = len(self.pages) - 1
        for i, p in enumerate(self.pages):
            if p["top"] <= r.top() < p["top"] + p["pix_h"]:
                page, pidx = p, i
                break
        local_top = r.top() - page["top"]
        x1 = r.left() / ZOOM
        x2 = (r.left() + r.width()) / ZOOM
        y2 = page["pt_h"] - local_top / ZOOM
        y1 = page["pt_h"] - (local_top + r.height()) / ZOOM
        return {"page": pidx, "box": (x1, y1, x2, y2)}


class SignWorker(QtCore.QThread):
    done = QtCore.Signal(bool, str)

    def __init__(self, args):
        super().__init__()
        self.args = args

    def run(self):
        try:
            from easysign_sign import signer

            signer.sign(**self.args)
            self.done.emit(True, self.args["output_path"])
        except Exception as e:
            self.done.emit(False, str(e))


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, path=None):
        super().__init__()
        self.setWindowTitle("easysign — sign PDF")
        self.resize(900, 1000)
        self.input_path = None
        self.worker = None
        self._order = 0
        self.entries = []

        self.view = PageView(self)
        self.setCentralWidget(self.view)

        tb = self.addToolBar("main")
        tb.addAction("Open…", self.open_file)
        self.cert_box = QtWidgets.QComboBox()
        self.cert_box.setMinimumWidth(260)
        self.cert_box.currentIndexChanged.connect(self.rerender_all)
        tb.addWidget(self.cert_box)
        self.act_place = tb.addAction("Add signature", self.arm)
        self.act_place.setCheckable(True)
        tb.addSeparator()
        self.reason = QtWidgets.QLineEdit()
        self.reason.setPlaceholderText("reason (optional)")
        self.location = QtWidgets.QLineEdit()
        self.location.setPlaceholderText("location (optional)")
        tb.addWidget(self.reason)
        tb.addWidget(self.location)
        self.act_sign = tb.addAction("Sign", self.do_sign)

        self.status = self.statusBar()
        self.load_certs()
        if path:
            self.load(path)
        self.update_sign_enabled()

    def arm(self):
        self.view.start_place()
        self.sync_mode_button()

    def sync_mode_button(self):
        self.act_place.setChecked(self.view.placing)

    def load_certs(self):
        try:
            self.entries = agent.list_entries()
        except Exception as e:
            self.entries = []
            self.status.showMessage(f"cert error: {e}")
        self.cert_box.clear()
        for e in self.entries:
            self.cert_box.addItem(e["label"])

    def current_entry(self):
        i = self.cert_box.currentIndex()
        if 0 <= i < len(self.entries):
            return self.entries[i]
        return None

    def current_appearance(self):
        entry = self.current_entry()
        cn, country = None, None
        if entry:
            try:
                cn, country = agent.subject_fields(entry["der"])
            except Exception:
                pass
            cn = cn or entry["label"].split(" (expires")[0]
        cn = cn or "signer"
        template = appearance.default_template(country)
        params = appearance.make_params(cn, appearance.now_when(), country)
        return template, params

    def open_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Open PDF", "", "PDF files (*.pdf)"
        )
        if path:
            self.load(path)

    def load(self, path):
        self.input_path = path
        self.view.load(path)
        self.setWindowTitle(f"easysign — {path}")
        self.update_sign_enabled()

    def add_box(self, rect):
        self._order += 1
        item = BoxItem(
            QtCore.QRectF(0, 0, rect.width(), rect.height()), self._order, self
        )
        item.setPos(rect.topLeft())
        self.view.scene().addItem(item)
        template, params = self.current_appearance()
        item.render(template, params)
        self.update_sign_enabled()

    def rerender_all(self):
        template, params = self.current_appearance()
        for it in self.view.scene().items():
            if isinstance(it, BoxItem):
                it.render(template, params)

    def boxes(self):
        items = [it for it in self.view.scene().items() if isinstance(it, BoxItem)]
        return sorted(items, key=lambda b: b.order)

    def update_sign_enabled(self):
        ready = bool(self.input_path) and self.worker is None
        self.act_sign.setEnabled(ready)
        self.act_place.setEnabled(bool(self.input_path))

    def do_sign(self):
        boxes = self.boxes()
        if boxes:
            placements = []
            for i, b in enumerate(boxes):
                pl = self.view.placement_for(b)
                pl["role"] = "signature" if i == 0 else "visual"
                placements.append(pl)
        else:
            # no appearance placed -> invisible signature
            placements = [{"role": "signature", "page": 0, "box": None}]

        entry = self.current_entry()
        if entry is None:
            QtWidgets.QMessageBox.critical(self, "easysign", "No certificate selected.")
            return
        default_out = self.input_path.replace(".pdf", "-signed.pdf")
        out, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save signed PDF", default_out, "PDF files (*.pdf)"
        )
        if not out:
            return
        args = {
            "input_path": self.input_path,
            "output_path": out,
            "credential_id": entry["credential_id"],
            "cert_der": entry["der"],
            "placements": placements,
            "reason": self.reason.text() or None,
            "location": self.location.text() or None,
        }
        self.status.showMessage("signing… enter the OTP in the popup window")
        self.worker = SignWorker(args)
        self.worker.done.connect(self.on_signed)
        self.update_sign_enabled()
        self.worker.start()

    def on_signed(self, ok, msg):
        self.worker = None
        self.update_sign_enabled()
        if ok:
            self.status.showMessage(f"signed → {msg}")
            QtWidgets.QMessageBox.information(self, "easysign", f"Signed:\n{msg}")
        else:
            self.status.showMessage("signing failed")
            QtWidgets.QMessageBox.critical(self, "easysign", f"Signing failed:\n{msg}")


def main():
    app = QtWidgets.QApplication(sys.argv)
    path = sys.argv[1] if len(sys.argv) > 1 else None
    win = MainWindow(path)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
