from unittest.mock import patch
from tui_certs.core.extractor import CertificateExtractor
from tui_certs.core.models import CertificateInfo


def test_certificate_info_creation():
    pem = "-----BEGIN CERTIFICATE-----\nMIIDDTCCAfWgAwIBAgIU...\n-----END CERTIFICATE-----"
    cert = CertificateInfo(pem, 0)
    assert cert.pem == pem
    assert cert.index == 0


@patch("tui_certs.core.extractor.CertificateExtractor._extract_with_openssl")
def test_extractor_success(mock_extract):
    extractor = CertificateExtractor("example.com")

    def side_effect():
        extractor.certificates = [CertificateInfo("dummy_pem", 0)]
        return True

    mock_extract.side_effect = side_effect
    assert extractor.extract() is True
    assert len(extractor.certificates) == 1
