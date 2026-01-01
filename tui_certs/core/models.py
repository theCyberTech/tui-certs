import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


@dataclass
class CertificateInfo:
    """Represents a parsed X.509 certificate with relevant details."""

    pem: str
    index: int = 0
    subject: Dict[str, str] = field(default_factory=dict)
    issuer: Dict[str, str] = field(default_factory=dict)
    serial_number: str = ""
    not_before: Optional[datetime.datetime] = None
    not_after: Optional[datetime.datetime] = None
    version: int = 0
    signature_algorithm: str = ""
    is_ca: bool = False
    san: List[str] = field(default_factory=list)
    fingerprint_sha256: str = ""

    def __post_init__(self):
        self._parse_certificate()

    def _parse_certificate(self) -> None:
        """Parse certificate details."""
        if HAS_CRYPTOGRAPHY:
            self._parse_with_cryptography()
        else:
            # Fallback to basic parsing (or OpenSSL if we move that logic here)
            # For now, let's keep it simple and refine in the next steps
            pass

    def _parse_with_cryptography(self) -> None:
        """Parse certificate using cryptography library."""
        try:
            cert = x509.load_pem_x509_certificate(self.pem.encode(), default_backend())

            # Subject and Issuer
            for attr in cert.subject:
                self.subject[attr.oid._name] = attr.value
            for attr in cert.issuer:
                self.issuer[attr.oid._name] = attr.value

            self.serial_number = f"{cert.serial_number:X}"
            self.not_before = cert.not_valid_before_utc
            self.not_after = cert.not_valid_after_utc
            self.version = cert.version.value
            self.signature_algorithm = cert.signature_algorithm_oid._name
            self.fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()

            # Extensions
            try:
                ext = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.BASIC_CONSTRAINTS
                )
                self.is_ca = ext.value.ca
            except x509.ExtensionNotFound:
                pass

            try:
                ext = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                self.san = ext.value.get_values_for_type(x509.GeneralName)
            except (x509.ExtensionNotFound, AttributeError):
                # Handle cases where get_values_for_type might fail or not be what we want
                try:
                    self.san = [str(name.value) for name in ext.value]
                except:
                    pass
        except Exception:
            pass

    def get_common_name(self) -> str:
        return self.subject.get("commonName", "Unknown")

    def get_issuer_cn(self) -> str:
        return self.issuer.get("commonName", "Unknown")

    def is_expired(self) -> bool:
        if not self.not_after:
            return False
        return self.not_after < datetime.datetime.now(datetime.timezone.utc)

    def get_validity_status(self) -> str:
        if self.is_expired():
            return "EXPIRED"
        return "Valid"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON export."""
        return {
            "index": self.index,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "version": self.version,
            "signature_algorithm": self.signature_algorithm,
            "is_ca": self.is_ca,
            "san": self.san,
            "fingerprint_sha256": self.fingerprint_sha256,
            "pem": self.pem,
        }
