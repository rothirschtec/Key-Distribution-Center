"""Web UI views for the KDC web application."""

from flask import flash, redirect, render_template, request, url_for

from ..services import CAService, CertificateService, TransferService
from . import web_bp


@web_bp.route("/")
def index():
    """Dashboard view."""
    cas = CAService.list_cas()
    cert_stats = CertificateService.get_certificate_stats()
    recent_certs = CertificateService.list_certificates()[:10]

    return render_template(
        "index.html",
        cas=cas,
        cert_stats=cert_stats,
        recent_certs=recent_certs,
    )


# CA Views
@web_bp.route("/cas")
def list_cas():
    """List all CAs."""
    cas = CAService.list_cas()
    return render_template("ca/list.html", cas=cas)


@web_bp.route("/cas/<domain>/<name>")
def ca_detail(domain: str, name: str):
    """CA detail view."""
    ca = CAService.get_ca(domain, name)
    if ca is None:
        flash(f"CA not found: {domain}_{name}", "error")
        return redirect(url_for("web.list_cas"))

    # Get certificates signed by this CA
    all_certs = CertificateService.list_certificates()
    ca_certs = [c for c in all_certs if f"-{name}" in c.get("cert_path", "")]

    return render_template("ca/detail.html", ca=ca, certificates=ca_certs)


@web_bp.route("/cas/create", methods=["GET", "POST"])
def create_ca():
    """Create CA view."""
    if request.method == "POST":
        result = CAService.create_ca(
            name=request.form["name"],
            domain=request.form["domain"],
            company=request.form["company"],
            country=request.form.get("country") or None,
            key_length=int(request.form["key_length"]) if request.form.get("key_length") else None,
            lifetime=int(request.form["lifetime"]) if request.form.get("lifetime") else None,
        )

        if result.success:
            flash(f"CA created: {result.data.get('name')}", "success")
            return redirect(url_for("web.list_cas"))
        else:
            flash(result.message, "error")

    return render_template("ca/create.html")


# Certificate Views
@web_bp.route("/certificates")
def list_certificates():
    """List all certificates."""
    show_expired = request.args.get("expired", "").lower() == "true"

    if show_expired:
        certs = CertificateService.get_expired_certificates()
    else:
        certs = CertificateService.list_certificates()

    return render_template("certificates/list.html", certificates=certs, show_expired=show_expired)


@web_bp.route("/certificates/<cn>")
def certificate_detail(cn: str):
    """Certificate detail view."""
    cert = CertificateService.get_certificate(cn)
    if cert is None:
        flash(f"Certificate not found: {cn}", "error")
        return redirect(url_for("web.list_certificates"))

    return render_template("certificates/detail.html", cert=cert)


@web_bp.route("/certificates/create", methods=["GET", "POST"])
def create_certificate():
    """Create certificate view."""
    cas = CAService.list_cas()

    if request.method == "POST":
        result = CertificateService.create_certificate(
            cn=request.form["cn"],
            ca_name=request.form["ca_name"],
            ca_domain=request.form["ca_domain"],
            company=request.form["company"],
            country=request.form.get("country") or None,
            key_length=int(request.form["key_length"]) if request.form.get("key_length") else None,
            lifetime=int(request.form["lifetime"]) if request.form.get("lifetime") else None,
            cert_type=request.form.get("cert_type", "user"),
        )

        if result.success:
            flash(f"Certificate created: {result.data.get('cn')}", "success")
            return redirect(url_for("web.list_certificates"))
        else:
            flash(result.message, "error")

    return render_template("certificates/create.html", cas=cas)


@web_bp.route("/certificates/<cn>/delete", methods=["POST"])
def delete_certificate(cn: str):
    """Delete certificate."""
    result = CertificateService.delete_certificate(cn)

    if result.success:
        flash(result.message, "success")
    else:
        flash(result.message, "error")

    return redirect(url_for("web.list_certificates"))


@web_bp.route("/certificates/<cn>/transfer", methods=["POST"])
def transfer_certificate(cn: str):
    """Transfer certificate to IPSEC gateway."""
    cert = CertificateService.get_certificate(cn)
    if cert is None:
        flash(f"Certificate not found: {cn}", "error")
        return redirect(url_for("web.list_certificates"))

    cert_path = cert.get("cert_path", f"STORE/certs/{cn}.pem")
    result = TransferService.transfer_certificate(cert_path)

    if result.success:
        flash("Certificate transferred successfully", "success")
    else:
        flash(f"Transfer failed: {result.message}", "error")

    return redirect(url_for("web.certificate_detail", cn=cn))


@web_bp.route("/certificates/<cn>/revoke", methods=["POST"])
def revoke_certificate(cn: str):
    """Revoke certificate."""
    cert = CertificateService.get_certificate(cn)
    if cert is None:
        flash(f"Certificate not found: {cn}", "error")
        return redirect(url_for("web.list_certificates"))

    cert_path = cert.get("cert_path", f"STORE/certs/{cn}.pem")
    result = TransferService.revoke_certificate(cert_path)

    if result.success:
        flash("Certificate revoked successfully", "success")
    else:
        flash(f"Revocation failed: {result.message}", "error")

    return redirect(url_for("web.list_certificates"))


@web_bp.route("/certificates/<cn>/reissue", methods=["POST"])
def reissue_certificate(cn: str):
    """Reissue certificate."""
    cert = CertificateService.get_certificate(cn)
    if cert is None:
        flash(f"Certificate not found: {cn}", "error")
        return redirect(url_for("web.list_certificates"))

    cert_path = cert.get("cert_path", f"STORE/certs/{cn}.pem")
    result = TransferService.reissue_certificate(cert_path)

    if result.success:
        flash("Certificate reissued successfully", "success")
    else:
        flash(f"Reissue failed: {result.message}", "error")

    return redirect(url_for("web.certificate_detail", cn=cn))
