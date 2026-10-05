# easysign-linux

Trans Sped issues qualified certificates whose private key stays in their cloud. On
Windows you sign with them and log into sites like ANAF through their EasySign app.
There is no Linux build. This is one.

It does two things:

- Lets Chrome/Chromium use the certificate for client authentication (ANAF SPV,
  fgo.ro, anything that asks for a client certificate).
- Signs PDFs (PAdES), from a GUI or the command line.

The key never leaves Trans Sped's cloud. Signing happens there over the Cloud Signature
Consortium (CSC) API. A background agent keeps the authorized session, so you enter your
signature password and SMS OTP once per session instead of once per action.

## Parts

- `easysign-agent` runs in the background, talks to mSign, holds the session, and shows
  the password/OTP window when something needs signing.
- `easysign-pkcs11.so` is a PKCS#11 module. Chrome loads it, sees your certificate (and
  the Trans Sped CA chain), and forwards signing to the agent.
- `easysign-gui` and `easysign-pdf` sign PDFs through the module.
- `easysign` manages your certificates and is useful for diagnostics.

## Requirements

Arch Linux or similar: `rust`/`cargo`, `python` 3.11+, `nss` (for `certutil` and
`modutil`), `zenity`, and Chrome/Chromium. The machine needs internet access since the
key is remote.

## Install

The one AUR dependency is `python-pyhanko`. Install it from the AUR with its check phase
skipped, then build easysign-linux from the local checkout:

```sh
yay -S python-pyhanko --mflags "--nocheck"
git clone <this repo> easysign-linux
cd easysign-linux
makepkg -si
```

`python-pyhanko` is installed first because `makepkg` resolves dependencies only from the
official repositories, not the AUR. The remaining dependencies come from the repos.

Then do the per-user setup once:

```sh
systemctl --user enable --now easysign-agent
modutil -add easysign -libfile /usr/lib/easysign/libeasysign_pkcs11.so \
    -dbdir sql:"$HOME/.pki/nssdb" -force
easysign profile add +40XXXXXXXXX
```

Restart Chrome so it loads the module.

The phone number is all that gets stored (in `~/.config/easysign/config`). Your password
and OTP are never saved. The agent looks certificates up by phone on each start, so a
renewed certificate is picked up on its own without re-adding anything.

## Logging in to a site

Log in as usual. When the site asks for a certificate, pick yours in Chrome's dialog,
then type your signature password and the SMS OTP in the window that appears.

## Signing a PDF

From the app menu, open "EasySign", or right-click a PDF and open it with that.
Or run:

```sh
easysign-gui document.pdf
```

Click a page to drop a signature, or drag to size it. Drag the corner to resize. Add it
on more pages if you want, then press Sign.

From a script:

```sh
easysign-pdf in.pdf out.pdf                                   # invisible
easysign-pdf --visible --anchor bottom-right in.pdf out.pdf   # visible, page 1
easysign-pdf --visible --anchor bottom-right \
    --stamp "2:360,40,560,100" in.pdf out.pdf                      # plus a copy on page 2
```

## More than one certificate

Run `easysign profile add` for each phone number. The agent exposes every certificate on
your accounts, and Chrome's dialog and the GUI dropdown let you choose.

## Managing it

```sh
easysign profile list
easysign certs
systemctl --user restart easysign-agent
```

## Uninstall

```sh
systemctl --user disable --now easysign-agent
modutil -delete easysign -dbdir sql:"$HOME/.pki/nssdb" -force
sudo pacman -R easysign-linux
rm -rf ~/.config/easysign   # your phone number(s), if you want them gone too
```

## Notes

A qualified signature needs a second factor, so the OTP cannot be skipped. It is reused
within a session, so you get one prompt per login or per signing run rather than one per
click. The cloud key is RSA PKCS#1 v1.5 (no PSS), so browser logins negotiate TLS 1.2.
