"""Web UI views for the KDC web application."""

from pathlib import Path

from flask import flash, redirect, render_template, request, send_file, url_for

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
        flash(f"CA not found: {domain}/{name}", "error")
        return redirect(url_for("web.list_cas"))

    # Get certificates signed by this CA
    ca_certs = CertificateService.list_certificates_by_ca(domain, name)

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


@web_bp.route("/cas/<domain>/<name>/delete", methods=["POST"])
def delete_ca(domain: str, name: str):
    """Delete a CA and all its certificates."""
    result = CAService.delete_ca(domain, name, delete_certificates=True)

    if result.success:
        cert_count = result.data.get("certificates_deleted", 0)
        flash(f"CA deleted: {domain}/{name} ({cert_count} certificates removed)", "success")
    else:
        flash(f"Failed to delete CA: {result.message}", "error")

    return redirect(url_for("web.list_cas"))


# Certificate Views
@web_bp.route("/certificates")
def list_certificates():
    """List all certificates."""
    show_expired = request.args.get("expired", "").lower() == "true"
    domain = request.args.get("domain")
    ca_name = request.args.get("ca")

    if show_expired:
        certs = CertificateService.get_expired_certificates()
    else:
        certs = CertificateService.list_certificates(domain=domain, ca_name=ca_name)

    # Get domains for filter dropdown
    domains = CAService.list_domains()

    return render_template(
        "certificates/list.html",
        certificates=certs,
        show_expired=show_expired,
        domains=domains,
        selected_domain=domain,
        selected_ca=ca_name,
    )


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
    domain = cert.get("domain")
    ca_name = cert.get("ca_name")

    result = TransferService.reissue_certificate(
        cert_path=cert_path,
        domain=domain,
        ca_name=ca_name,
    )

    if result.success:
        new_cert_path = result.data.get("cert_path", "")
        flash(f"Certificate reissued: {result.message}", "success")
    else:
        flash(f"Reissue failed: {result.message}", "error")
        if result.error:
            flash(f"Error details: {result.error}", "error")

    # Use the new CN from result data if available (in case it changed)
    new_cn = result.data.get("cn", cn) if result.data else cn
    return redirect(url_for("web.certificate_detail", cn=new_cn))


@web_bp.route("/certificates/<cn>/download/p12")
def download_p12(cn: str):
    """Download P12 bundle for a certificate."""
    cert = CertificateService.get_certificate(cn)
    if cert is None:
        flash(f"Certificate not found: {cn}", "error")
        return redirect(url_for("web.list_certificates"))

    p12_path = cert.get("p12_path")
    if not p12_path:
        flash("No P12 bundle available for this certificate", "error")
        return redirect(url_for("web.certificate_detail", cn=cn))

    p12_file = Path(p12_path)
    if not p12_file.exists():
        flash("P12 file not found on disk", "error")
        return redirect(url_for("web.certificate_detail", cn=cn))

    return send_file(
        p12_file,
        as_attachment=True,
        download_name=p12_file.name,
        mimetype="application/x-pkcs12"
    )


@web_bp.route("/certificates/<cn>/generate-p12", methods=["POST"])
def generate_p12(cn: str):
    """Generate P12 bundle for a certificate."""
    cert = CertificateService.get_certificate(cn)
    if cert is None:
        flash(f"Certificate not found: {cn}", "error")
        return redirect(url_for("web.list_certificates"))

    # Get company from cert info or use default
    company = cert.get("subject_o", "Unknown")

    result = CertificateService.generate_p12(
        cn=cn,
        domain=cert.get("domain"),
        ca_name=cert.get("ca_name"),
        company=company,
    )

    if result.success:
        flash("P12 bundle generated successfully", "success")
    else:
        flash(f"Failed to generate P12: {result.message}", "error")

    return redirect(url_for("web.certificate_detail", cn=cn))


@web_bp.route("/certificates/<cn>/download/vpn-bundle/<target_os>")
def download_vpn_bundle(cn: str, target_os: str):
    """Download VPN setup bundle for a certificate.

    Args:
        cn: Certificate Common Name.
        target_os: Target OS (linux, mac, windows).
    """
    if target_os not in ("linux", "mac", "windows"):
        flash(f"Invalid target OS: {target_os}", "error")
        return redirect(url_for("web.certificate_detail", cn=cn))

    cert = CertificateService.get_certificate(cn)
    if cert is None:
        flash(f"Certificate not found: {cn}", "error")
        return redirect(url_for("web.list_certificates"))

    result = CertificateService.generate_vpn_bundle(
        cn=cn,
        target_os=target_os,
        domain=cert.get("domain"),
        ca_name=cert.get("ca_name"),
    )

    if result is None:
        flash("Failed to generate VPN bundle. Ensure P12 exists.", "error")
        return redirect(url_for("web.certificate_detail", cn=cn))

    zip_buffer, filename = result

    return send_file(
        zip_buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/zip"
    )
