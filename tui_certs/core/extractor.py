import ssl
import socket
import subprocess
import re
import base64
from typing import List, Optional, Dict, Any
from .models import CertificateInfo


class CertificateExtractor:
    """Handles TLS connection and certificate chain extraction."""

    def __init__(self, hostname: str, port: int = 443, timeout: int = 10):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        self.certificates: List[CertificateInfo] = []
        self.error: Optional[str] = None
        self.connection_info: Dict[str, Any] = {}

    def extract(self) -> bool:
        """Extract certificate chain from the target server."""
        self.certificates = []
        self.error = None

        # First try using OpenSSL command-line for full chain
        if self._extract_with_openssl():
            return True

        # Fallback to ssl module
        return self._extract_with_ssl_module()

    def _extract_with_openssl(self) -> bool:
        """Extract certificate chain using OpenSSL command-line tool."""
        try:
            cmd = [
                "openssl",
                "s_client",
                "-connect",
                f"{self.hostname}:{self.port}",
                "-showcerts",
                "-servername",
                self.hostname,
            ]

            result = subprocess.run(
                cmd, input=b"", capture_output=True, timeout=self.timeout + 5
            )

            if result.returncode != 0 and not result.stdout:
                return False

            output = result.stdout.decode("utf-8", errors="replace")
            pem_pattern = r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)"
            matches = re.findall(pem_pattern, output, re.DOTALL)

            if not matches:
                return False

            for idx, pem in enumerate(matches):
                cert = CertificateInfo(pem.strip(), idx)
                self.certificates.append(cert)

            self._parse_connection_info(output)
            return True

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.error = str(e)
            return False

    def _extract_with_ssl_module(self) -> bool:
        """Extract certificate using Python's ssl module (fallback)."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (self.hostname, self.port), timeout=self.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        pem = (
                            "-----BEGIN CERTIFICATE-----\n"
                            + base64.encodebytes(der_cert).decode("ascii")
                            + "-----END CERTIFICATE-----"
                        )
                        cert = CertificateInfo(pem, 0)
                        self.certificates.append(cert)
                        self.connection_info = {
                            "protocol": ssock.version(),
                            "cipher": ssock.cipher(),
                        }
                        return True
            self.error = "No certificate received"
            return False
        except Exception as e:
            self.error = str(e)
            return False

    def _parse_connection_info(self, output: str) -> None:
        """Parse connection info from OpenSSL s_client output."""
        proto_match = re.search(r"Protocol\s*:\s*(\S+)", output)
        if proto_match:
            self.connection_info["protocol"] = proto_match.group(1)

        cipher_match = re.search(r"Cipher\s*:\s*(\S+)", output)
        if cipher_match:
            self.connection_info["cipher"] = cipher_match.group(1)

        verify_match = re.search(r"Verify return code:\s*(\d+)\s*\(([^)]+)\)", output)
        if verify_match:
            self.connection_info["verify_code"] = int(verify_match.group(1))
            self.connection_info["verify_message"] = verify_match.group(2)
