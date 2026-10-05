"""Talk to easysign-agent over its Unix socket (the same protocol the PKCS#11
module uses). Lets the PDF signer list certificates and sign without going through
the browser module or python-pkcs11."""
import json
import os
import socket
import sys
import tempfile


def socket_path():
    rt = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
    return os.path.join(rt, "easysign-agent.sock")


def _connect():
    s = socket.socket(socket.AF_UNIX)
    try:
        s.connect(socket_path())
    except OSError as e:
        raise RuntimeError(
            "cannot reach easysign-agent "
            "(systemctl --user start easysign-agent): " + str(e)
        )
    return s


def _call(request):
    """Send one request, return the single response (for non-interactive calls)."""
    s = _connect()
    try:
        s.sendall((json.dumps(request) + "\n").encode())
        line = s.makefile("r").readline()
    finally:
        s.close()
    if not line:
        raise RuntimeError("easysign-agent closed the connection")
    return json.loads(line)


def list_entries():
    """[{credential_id, account, label, der(bytes)}] for the signing certificates."""
    resp = _call("ListCerts")
    if "Error" in resp:
        raise RuntimeError(resp["Error"])
    out = []
    for c in resp["Certs"]:
        out.append(
            {
                "credential_id": c["credential_id"],
                "account": c["account"],
                "label": c["label"] or c["credential_id"],
                "der": bytes(c["der"]),
            }
        )
    return out


def subject_fields(der):
    from asn1crypto import x509

    subj = x509.Certificate.load(der).subject.native
    return subj.get("common_name"), subj.get("country_name")


def sign(credential_id, digest, algo, prompt=None):
    """Sign `digest` (raw hash bytes) with the given credential. `algo` is one of
    'Sha256Rsa', 'Sha512Rsa', 'RawRsa'. Answers the agent's credential prompt."""
    prompt = prompt or default_prompt
    s = _connect()
    try:
        f = s.makefile("r")
        req = {
            "Sign": {
                "credential_id": credential_id,
                "hash": list(digest),
                "algo": algo,
            }
        }
        s.sendall((json.dumps(req) + "\n").encode())
        while True:
            line = f.readline()
            if not line:
                raise RuntimeError("easysign-agent closed the connection")
            resp = json.loads(line)
            if "Signature" in resp:
                return bytes(resp["Signature"])
            if "Error" in resp:
                raise RuntimeError(resp["Error"])
            if "NeedCredentials" in resp:
                nc = resp["NeedCredentials"]
                password, otp = prompt(nc["ask_password"], nc["label"])
                s.sendall(
                    (json.dumps({"Credentials": {"password": password, "otp": otp}})
                     + "\n").encode()
                )
            else:
                raise RuntimeError("unexpected response: %r" % resp)
    finally:
        s.close()


def default_prompt(ask_password, label):
    """Ask for the signature password (first time) and the OTP. Terminal when one is
    attached, otherwise single-field zenity dialogs (which submit on Enter)."""
    if sys.stdin and sys.stdin.isatty():
        import getpass

        password = (
            getpass.getpass(f"Signature password for {label}: ")
            if ask_password
            else None
        )
        otp = input("OTP (SMS): ").strip()
        return password, otp

    password = (
        _zenity(f"Signature password for {label}", hide=True) if ask_password else None
    )
    otp = _zenity(f"Sign in to {label}\nEnter the OTP (SMS)").strip()
    return password, otp


def _zenity(text, hide=False):
    import subprocess

    args = ["zenity", "--entry", "--title=EasySign", "--text", text]
    if hide:
        args.append("--hide-text")
    out = subprocess.run(args, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError("prompt cancelled")
    return out.stdout.rstrip("\n")
