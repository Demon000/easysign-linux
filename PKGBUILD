# Maintainer: Cosmin-Gabriel Tanislav <cozzmy13@gmail.com>
pkgname=easysign-linux
pkgver=0.1.0
pkgrel=1
pkgdesc="Trans Sped mSign cloud certificate on Linux: browser client-auth and PDF signing"
arch=('x86_64')
url="https://github.com/demon000/easysign-linux"
license=('MIT')
depends=('nss' 'python' 'zenity' 'pyside6' 'python-pymupdf' 'python-pillow'
         'python-pyhanko')
makedepends=('rust')
install="$pkgname.install"
source=()

build() {
    cargo build --release --locked \
        --manifest-path "$startdir/Cargo.toml" \
        --target-dir "$srcdir/target"
}

package() {
    cd "$startdir"

    install -Dm755 "$srcdir/target/release/easysign" \
        "$pkgdir/usr/bin/easysign"
    install -Dm755 "$srcdir/target/release/easysign-agent" \
        "$pkgdir/usr/bin/easysign-agent"
    install -Dm755 "$srcdir/target/release/libeasysign_pkcs11.so" \
        "$pkgdir/usr/lib/easysign/libeasysign_pkcs11.so"

    install -Dm644 packaging/easysign-agent.service \
        "$pkgdir/usr/lib/systemd/user/easysign-agent.service"

    install -Dm755 packaging/easysign-gui "$pkgdir/usr/bin/easysign-gui"
    install -Dm755 packaging/easysign-pdf "$pkgdir/usr/bin/easysign-pdf"
    install -Dm644 pdf/sign_pdf.py "$pkgdir/usr/share/easysign/sign_pdf.py"
    install -Dm644 pdf/gui.py "$pkgdir/usr/share/easysign/gui.py"
    install -Dm644 -t "$pkgdir/usr/share/easysign/easysign_sign" \
        pdf/easysign_sign/*.py

    install -Dm644 packaging/easysign.desktop \
        "$pkgdir/usr/share/applications/easysign.desktop"
}
