"""WTForms for the KDC web application."""

from flask_wtf import FlaskForm
from wtforms import IntegerField, SelectField, StringField
from wtforms.validators import DataRequired, Length, NumberRange, Optional


class CreateCAForm(FlaskForm):
    """Form for creating a Certificate Authority."""

    name = StringField(
        "CA Name",
        validators=[DataRequired(), Length(min=1, max=64)],
        description="Short name for the CA (e.g., 'myca')",
    )
    domain = StringField(
        "Domain",
        validators=[DataRequired(), Length(min=1, max=255)],
        description="Domain for the CA (e.g., 'example.com')",
    )
    company = StringField(
        "Company",
        validators=[DataRequired(), Length(min=1, max=255)],
        description="Company name for the DN",
    )
    country = StringField(
        "Country",
        validators=[Optional(), Length(min=2, max=2)],
        default="AT",
        description="Two-letter country code (e.g., 'AT')",
    )
    key_length = IntegerField(
        "Key Length",
        validators=[Optional(), NumberRange(min=2048, max=8192)],
        default=4096,
        description="RSA key size in bits",
    )
    lifetime = IntegerField(
        "Lifetime (days)",
        validators=[Optional(), NumberRange(min=1, max=36500)],
        default=3650,
        description="CA validity period in days",
    )


class CreateCertificateForm(FlaskForm):
    """Form for creating a certificate."""

    cn = StringField(
        "Common Name",
        validators=[DataRequired(), Length(min=1, max=255)],
        description="Common Name for the certificate",
    )
    ca_name = StringField(
        "CA Name",
        validators=[DataRequired()],
        description="Name of the signing CA",
    )
    ca_domain = StringField(
        "CA Domain",
        validators=[DataRequired()],
        description="Domain of the signing CA",
    )
    company = StringField(
        "Company",
        validators=[DataRequired(), Length(min=1, max=255)],
        description="Company name for the DN",
    )
    country = StringField(
        "Country",
        validators=[Optional(), Length(min=2, max=2)],
        default="AT",
        description="Two-letter country code",
    )
    key_length = IntegerField(
        "Key Length",
        validators=[Optional(), NumberRange(min=2048, max=8192)],
        default=3072,
        description="RSA key size in bits",
    )
    lifetime = IntegerField(
        "Lifetime (days)",
        validators=[Optional(), NumberRange(min=1, max=3650)],
        default=181,
        description="Certificate validity period in days",
    )
    cert_type = SelectField(
        "Certificate Type",
        choices=[
            ("user", "User"),
            ("vpn", "VPN Gateway"),
            ("host", "Host"),
        ],
        default="user",
        description="Type of certificate to create",
    )
