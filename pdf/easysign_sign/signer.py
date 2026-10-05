"""Shared signing core: stamp the appearance as vector text on any 'visual' pages,
then apply one PAdES signature at the 'signature' box. Signing goes to easysign-agent
over its socket, so no PKCS#11 module or python-pkcs11 is involved here."""
import hashlib
import io

from asn1crypto import x509
from pyhanko.sign.signers import Signer
from pyhanko_certvalidator.registry import SimpleCertificateStore

from . import agent, appearance

FIELD_NAME = "Signature1"
_DIGEST_ALGO = {"sha256": "Sha256Rsa", "sha512": "Sha512Rsa"}


class AgentSigner(Signer):
    """A pyHanko Signer whose raw RSA signature is produced by easysign-agent."""

    def __init__(self, credential_id, cert_der, prompt=None):
        cert = x509.Certificate.load(cert_der)
        super().__init__(
            signing_cert=cert,
            cert_registry=SimpleCertificateStore(),
            signature_mechanism=None,
        )
        self.credential_id = credential_id
        self.prompt = prompt
        self._sig_len = cert.public_key.bit_size // 8

    async def async_sign_raw(self, data, digest_algorithm, dry_run=False):
        if dry_run:
            return b"\0" * self._sig_len
        algo = _DIGEST_ALGO.get(digest_algorithm.lower())
        if algo is None:
            raise ValueError(f"unsupported digest {digest_algorithm}")
        digest = hashlib.new(digest_algorithm.lower(), data).digest()
        return agent.sign(self.credential_id, digest, algo, self.prompt)


def _style_for(tpl, params, box):
    w, h = box[2] - box[0], box[3] - box[1]
    return appearance.make_style(
        tpl, font_size=appearance.auto_font_size(w, h, tpl, params)
    )


def _stamp_visuals(pdf_bytes, tpl, params, visuals):
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils.layout import BoxConstraints
    from pyhanko.stamp import TextStamp

    w = IncrementalPdfFileWriter(io.BytesIO(pdf_bytes))
    for p in visuals:
        x1, y1, x2, y2 = p["box"]
        box = BoxConstraints(width=int(round(x2 - x1)), height=int(round(y2 - y1)))
        style = _style_for(tpl, params, p["box"])
        TextStamp(w, style, text_params=params, box=box).apply(p["page"], x1, y1)
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


def sign(
    input_path,
    output_path,
    credential_id,
    cert_der,
    placements,
    reason=None,
    location=None,
    template=None,
    prompt=None,
):
    """placements: list of {page:int (0-based), box:(x1,y1,x2,y2) PDF pts,
    role:'signature'|'visual'}. Exactly one 'signature'."""
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers
    from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter

    sigs = [p for p in placements if p["role"] == "signature"]
    visuals = [p for p in placements if p["role"] == "visual"]
    if len(sigs) != 1:
        raise ValueError("exactly one 'signature' placement is required")
    sig = sigs[0]

    cn, country = agent.subject_fields(cert_der)
    signer_name = cn or credential_id
    tpl = template or appearance.default_template(country)
    params = appearance.make_params(signer_name, appearance.now_when(), country)

    data = open(input_path, "rb").read()
    if visuals:
        data = _stamp_visuals(data, tpl, params, visuals)

    meta = signers.PdfSignatureMetadata(
        field_name=FIELD_NAME,
        md_algorithm="sha256",
        reason=reason,
        location=location,
        subfilter=SigSeedSubFilter.PADES,
        embed_validation_info=False,
    )
    visible = sig.get("box") is not None
    field_spec = SigFieldSpec(
        sig_field_name=FIELD_NAME,
        on_page=sig["page"],
        box=sig["box"] if visible else None,
    )
    sig_style = _style_for(tpl, params, sig["box"]) if visible else None

    pdf_signer = signers.PdfSigner(
        meta,
        signer=AgentSigner(credential_id, cert_der, prompt),
        stamp_style=sig_style,
        new_field_spec=field_spec,
    )
    w = IncrementalPdfFileWriter(io.BytesIO(data))
    with open(output_path, "wb") as outf:
        pdf_signer.sign_pdf(
            w,
            appearance_text_params=params if visible else None,
            output=outf,
        )
