import re
import json
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Optional
from .models import CertificateInfo


class CertificateStorage:
    """Handles saving and loading certificates from disk."""

    def __init__(self, base_dir: Optional[str] = None):
        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            self.base_dir = Path.home() / ".tui_certs"
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        """Ensure the storage directory exists."""
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def save_certificate(
        self, cert: CertificateInfo, hostname: str, filename: Optional[str] = None
    ) -> Path:
        """Save a certificate as a PEM file."""
        if filename:
            safe_name = re.sub(r"[^\w\-_.]", "_", filename)
        else:
            cn = cert.get_common_name()
            safe_cn = re.sub(r"[^\w\-_.]", "_", cn)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = f"{safe_cn}_{timestamp}.pem"

        host_dir = self.base_dir / re.sub(r"[^\w\-_.]", "_", hostname)
        host_dir.mkdir(parents=True, exist_ok=True)
        file_path = host_dir / safe_name

        counter = 1
        while file_path.exists():
            name_parts = safe_name.rsplit(".", 1)
            if len(name_parts) == 2:
                file_path = host_dir / f"{name_parts[0]}_{counter}.{name_parts[1]}"
            else:
                file_path = host_dir / f"{safe_name}_{counter}"
            counter += 1

        with open(file_path, "w") as f:
            f.write(cert.pem)
            f.write("\n")

        return file_path

    def export_json(
        self, certs: List[CertificateInfo], hostname: str, file_path: Path
    ) -> None:
        """Export certificate chain details to JSON."""
        data = {
            "hostname": hostname,
            "timestamp": datetime.now().isoformat(),
            "chain": [cert.to_dict() for cert in certs],
        }
        with open(file_path, "w") as f:
            json.dump(data, f, indent=4)

    def list_saved_certificates(self) -> List[Tuple[str, Path]]:
        """List all saved certificates."""
        results = []
        if not self.base_dir.exists():
            return results

        for host_dir in sorted(self.base_dir.iterdir()):
            if host_dir.is_dir():
                for cert_file in sorted(host_dir.glob("*.pem")):
                    display = f"{host_dir.name}/{cert_file.name}"
                    results.append((display, cert_file))
        return results

    def read_certificate(self, path: Path) -> Optional[CertificateInfo]:
        """Read a certificate from a file."""
        try:
            with open(path, "r") as f:
                pem = f.read()
            return CertificateInfo(pem, 0)
        except Exception:
            return None

    def delete_certificate(self, path: Path) -> bool:
        """Delete a saved certificate file."""
        try:
            path.unlink()
            parent = path.parent
            if parent != self.base_dir and not any(parent.iterdir()):
                parent.rmdir()
            return True
        except Exception:
            return False
