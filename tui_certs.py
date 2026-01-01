#!/usr/bin/env python3
"""
TUI Certificate Chain Extractor
================================
A command-line Text User Interface (TUI) application for extracting,
viewing, and saving TLS certificate chains from remote servers.

Features:
- Connect to any hostname/IP with optional port (default: 443)
- Extract full certificate chain (leaf + intermediates)
- Display certificates in readable format
- Select and save certificates as PEM files
- View previously saved certificates
- Cross-platform support (Linux, macOS, Windows)

Requirements:
- Python 3.6+
- Standard library only (ssl, curses, socket, subprocess)
- Optional: OpenSSL command-line tool for enhanced chain extraction

Usage:
    python tui_certs.py

Author: TUI Certificate Extractor
License: MIT
"""

import ssl
import socket
import subprocess
import os
import sys
import re
import platform
from datetime import datetime
from typing import List, Tuple, Optional, Dict, Any
from pathlib import Path

# Handle curses import for cross-platform compatibility
if platform.system() == "Windows":
    # Windows doesn't have curses by default, use windows-curses if available
    try:
        import curses
        CURSES_AVAILABLE = True
    except ImportError:
        CURSES_AVAILABLE = False
        print("Note: For full TUI experience on Windows, install windows-curses:")
        print("  pip install windows-curses")
        print("Falling back to simple text interface...")
else:
    import curses
    CURSES_AVAILABLE = True


# ============================================================================
# Certificate Extraction Module
# ============================================================================

class CertificateInfo:
    """Represents a parsed X.509 certificate with relevant details."""

    def __init__(self, pem: str, index: int = 0):
        self.pem = pem
        self.index = index
        self.subject: Dict[str, str] = {}
        self.issuer: Dict[str, str] = {}
        self.serial_number: str = ""
        self.not_before: str = ""
        self.not_after: str = ""
        self.version: int = 0
        self.signature_algorithm: str = ""
        self.is_ca: bool = False
        self.san: List[str] = []
        self.fingerprint_sha256: str = ""
        self._parse_certificate()

    def _parse_certificate(self) -> None:
        """Parse certificate details using OpenSSL or ssl module."""
        try:
            self._parse_with_openssl()
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            self._parse_basic()

    def _parse_with_openssl(self) -> None:
        """Parse certificate using OpenSSL command-line tool."""
        # Get subject
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-nameopt", "multiline"],
            input=self.pem.encode(),
            capture_output=True,
            timeout=10
        )
        if result.returncode == 0:
            self._parse_name_field(result.stdout.decode(), self.subject)

        # Get issuer
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-issuer", "-nameopt", "multiline"],
            input=self.pem.encode(),
            capture_output=True,
            timeout=10
        )
        if result.returncode == 0:
            self._parse_name_field(result.stdout.decode(), self.issuer)

        # Get dates
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-dates"],
            input=self.pem.encode(),
            capture_output=True,
            timeout=10
        )
        if result.returncode == 0:
            output = result.stdout.decode()
            for line in output.strip().split('\n'):
                if line.startswith('notBefore='):
                    self.not_before = line.split('=', 1)[1].strip()
                elif line.startswith('notAfter='):
                    self.not_after = line.split('=', 1)[1].strip()

        # Get serial number
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-serial"],
            input=self.pem.encode(),
            capture_output=True,
            timeout=10
        )
        if result.returncode == 0:
            output = result.stdout.decode().strip()
            if '=' in output:
                self.serial_number = output.split('=', 1)[1]

        # Get fingerprint
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-fingerprint", "-sha256"],
            input=self.pem.encode(),
            capture_output=True,
            timeout=10
        )
        if result.returncode == 0:
            output = result.stdout.decode().strip()
            if '=' in output:
                self.fingerprint_sha256 = output.split('=', 1)[1]

        # Get text output for additional fields
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-text"],
            input=self.pem.encode(),
            capture_output=True,
            timeout=10
        )
        if result.returncode == 0:
            text = result.stdout.decode()

            # Extract signature algorithm
            sig_match = re.search(r'Signature Algorithm:\s*(.+)', text)
            if sig_match:
                self.signature_algorithm = sig_match.group(1).strip()

            # Extract version
            ver_match = re.search(r'Version:\s*(\d+)', text)
            if ver_match:
                self.version = int(ver_match.group(1))

            # Check if CA
            self.is_ca = "CA:TRUE" in text

            # Extract SAN
            san_match = re.search(
                r'X509v3 Subject Alternative Name:.*?\n\s*(.+?)(?:\n\s*X509v3|\n\s*Signature|$)',
                text,
                re.DOTALL
            )
            if san_match:
                san_text = san_match.group(1).strip()
                self.san = [s.strip() for s in san_text.split(',')]

    def _parse_name_field(self, output: str, target: Dict[str, str]) -> None:
        """Parse X.509 name field from OpenSSL multiline output."""
        for line in output.strip().split('\n'):
            if '=' in line:
                key, _, value = line.strip().partition('=')
                key = key.strip()
                value = value.strip()
                if key and value:
                    target[key] = value

    def _parse_basic(self) -> None:
        """Basic parsing fallback when OpenSSL is not available."""
        # Try to extract basic info from PEM using regex patterns
        # This is a minimal fallback
        self.subject = {"CN": "Unable to parse (OpenSSL not available)"}
        self.issuer = {"CN": "Unable to parse (OpenSSL not available)"}

    def get_common_name(self) -> str:
        """Get the Common Name from the subject."""
        return self.subject.get('commonName',
               self.subject.get('CN', 'Unknown'))

    def get_issuer_cn(self) -> str:
        """Get the Common Name from the issuer."""
        return self.issuer.get('commonName',
               self.issuer.get('CN', 'Unknown'))

    def get_display_name(self) -> str:
        """Get a display-friendly name for the certificate."""
        cn = self.get_common_name()
        cert_type = "CA" if self.is_ca else "Leaf"
        return f"[{self.index}] {cn} ({cert_type})"

    def is_expired(self) -> bool:
        """Check if the certificate is expired."""
        if not self.not_after:
            return False
        try:
            # Try common date formats
            for fmt in ["%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"]:
                try:
                    exp_date = datetime.strptime(self.not_after, fmt)
                    return exp_date < datetime.now()
                except ValueError:
                    continue
            return False
        except Exception:
            return False

    def get_validity_status(self) -> str:
        """Get a string describing the validity status."""
        if self.is_expired():
            return "EXPIRED"
        return "Valid"

    def format_details(self, width: int = 80) -> List[str]:
        """Format certificate details for display."""
        lines = []
        lines.append("=" * width)
        lines.append(f"Certificate [{self.index}]".center(width))
        lines.append("=" * width)
        lines.append("")

        # Subject
        lines.append("Subject:")
        for key, value in self.subject.items():
            lines.append(f"  {key}: {value}")
        lines.append("")

        # Issuer
        lines.append("Issuer:")
        for key, value in self.issuer.items():
            lines.append(f"  {key}: {value}")
        lines.append("")

        # Validity
        lines.append("Validity:")
        lines.append(f"  Not Before: {self.not_before}")
        lines.append(f"  Not After:  {self.not_after}")
        lines.append(f"  Status:     {self.get_validity_status()}")
        lines.append("")

        # Technical details
        lines.append("Technical Details:")
        lines.append(f"  Serial Number: {self.serial_number}")
        lines.append(f"  Version: {self.version}")
        lines.append(f"  Signature Algorithm: {self.signature_algorithm}")
        lines.append(f"  Is CA: {self.is_ca}")
        lines.append("")

        # SAN
        if self.san:
            lines.append("Subject Alternative Names:")
            for name in self.san[:10]:  # Limit to first 10
                lines.append(f"  {name}")
            if len(self.san) > 10:
                lines.append(f"  ... and {len(self.san) - 10} more")
            lines.append("")

        # Fingerprint
        if self.fingerprint_sha256:
            lines.append(f"SHA-256 Fingerprint:")
            lines.append(f"  {self.fingerprint_sha256}")

        lines.append("")
        return lines


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
        """
        Extract certificate chain from the target server.
        Returns True on success, False on failure.
        """
        self.certificates = []
        self.error = None

        # First try using OpenSSL command-line for full chain
        if self._extract_with_openssl():
            return True

        # Fallback to ssl module (may not get full chain)
        return self._extract_with_ssl_module()

    def _extract_with_openssl(self) -> bool:
        """Extract certificate chain using OpenSSL command-line tool."""
        try:
            # Use s_client to get full chain
            cmd = [
                "openssl", "s_client",
                "-connect", f"{self.hostname}:{self.port}",
                "-showcerts",
                "-servername", self.hostname  # SNI support
            ]

            result = subprocess.run(
                cmd,
                input=b"",  # Send empty input to close connection
                capture_output=True,
                timeout=self.timeout + 5
            )

            output = result.stdout.decode('utf-8', errors='replace')

            # Extract all certificates from the output
            pem_pattern = r'(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)'
            matches = re.findall(pem_pattern, output, re.DOTALL)

            if not matches:
                return False

            for idx, pem in enumerate(matches):
                cert = CertificateInfo(pem.strip(), idx)
                self.certificates.append(cert)

            # Extract connection info
            self._parse_connection_info(output)

            return True

        except subprocess.TimeoutExpired:
            self.error = f"Connection timed out after {self.timeout} seconds"
            return False
        except FileNotFoundError:
            # OpenSSL not available
            return False
        except Exception as e:
            self.error = f"OpenSSL error: {str(e)}"
            return False

    def _extract_with_ssl_module(self) -> bool:
        """Extract certificate using Python's ssl module (fallback)."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (self.hostname, self.port),
                timeout=self.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # Get peer certificate in DER format
                    der_cert = ssock.getpeercert(binary_form=True)

                    if der_cert:
                        # Convert DER to PEM
                        import base64
                        pem = (
                            "-----BEGIN CERTIFICATE-----\n" +
                            base64.encodebytes(der_cert).decode('ascii') +
                            "-----END CERTIFICATE-----"
                        )
                        cert = CertificateInfo(pem, 0)
                        self.certificates.append(cert)

                        self.connection_info = {
                            'protocol': ssock.version(),
                            'cipher': ssock.cipher()
                        }

                        return True

            self.error = "No certificate received from server"
            return False

        except socket.timeout:
            self.error = f"Connection timed out after {self.timeout} seconds"
            return False
        except socket.gaierror as e:
            self.error = f"DNS resolution failed: {e}"
            return False
        except ConnectionRefusedError:
            self.error = f"Connection refused by {self.hostname}:{self.port}"
            return False
        except ssl.SSLError as e:
            self.error = f"SSL/TLS error: {e}"
            return False
        except OSError as e:
            self.error = f"Connection error: {e}"
            return False
        except Exception as e:
            self.error = f"Unexpected error: {type(e).__name__}: {e}"
            return False

    def _parse_connection_info(self, output: str) -> None:
        """Parse connection info from OpenSSL s_client output."""
        # Protocol version
        proto_match = re.search(r'Protocol\s*:\s*(\S+)', output)
        if proto_match:
            self.connection_info['protocol'] = proto_match.group(1)

        # Cipher
        cipher_match = re.search(r'Cipher\s*:\s*(\S+)', output)
        if cipher_match:
            self.connection_info['cipher'] = cipher_match.group(1)

        # Verify return code
        verify_match = re.search(r'Verify return code:\s*(\d+)\s*\(([^)]+)\)', output)
        if verify_match:
            self.connection_info['verify_code'] = int(verify_match.group(1))
            self.connection_info['verify_message'] = verify_match.group(2)


class CertificateStorage:
    """Handles saving and loading certificates from disk."""

    def __init__(self, base_dir: str = ""):
        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            self.base_dir = Path.home() / ".tui_certs"
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        """Ensure the storage directory exists."""
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def save_certificate(self, cert: CertificateInfo,
                        hostname: str,
                        filename: Optional[str] = None) -> Path:
        """
        Save a certificate as a PEM file.
        Returns the path to the saved file.
        """
        if filename:
            safe_name = re.sub(r'[^\w\-_.]', '_', filename)
        else:
            cn = cert.get_common_name()
            safe_cn = re.sub(r'[^\w\-_.]', '_', cn)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = f"{safe_cn}_{timestamp}.pem"

        # Create hostname subdirectory
        host_dir = self.base_dir / re.sub(r'[^\w\-_.]', '_', hostname)
        host_dir.mkdir(parents=True, exist_ok=True)

        file_path = host_dir / safe_name

        # Ensure unique filename
        counter = 1
        while file_path.exists():
            name_parts = safe_name.rsplit('.', 1)
            if len(name_parts) == 2:
                file_path = host_dir / f"{name_parts[0]}_{counter}.{name_parts[1]}"
            else:
                file_path = host_dir / f"{safe_name}_{counter}"
            counter += 1

        with open(file_path, 'w') as f:
            f.write(cert.pem)
            f.write('\n')

        return file_path

    def list_saved_certificates(self) -> List[Tuple[str, Path]]:
        """List all saved certificates with their display names and paths."""
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
            with open(path, 'r') as f:
                pem = f.read()
            return CertificateInfo(pem, 0)
        except Exception:
            return None

    def delete_certificate(self, path: Path) -> bool:
        """Delete a saved certificate file."""
        try:
            path.unlink()
            # Remove parent directory if empty
            parent = path.parent
            if parent != self.base_dir and not any(parent.iterdir()):
                parent.rmdir()
            return True
        except Exception:
            return False


# ============================================================================
# TUI Module (Curses-based)
# ============================================================================

if CURSES_AVAILABLE:

    class TUIApp:
        """Main TUI application using curses."""

        def __init__(self, stdscr):
            self.stdscr = stdscr
            self.storage = CertificateStorage()
            self.current_certificates: List[CertificateInfo] = []
            self.current_hostname: str = ""
            self.message: str = ""
            self.message_type: str = "info"  # info, success, error

            # Initialize curses settings
            curses.curs_set(0)  # Hide cursor
            curses.start_color()
            curses.use_default_colors()

            # Define color pairs
            curses.init_pair(1, curses.COLOR_GREEN, -1)   # Success
            curses.init_pair(2, curses.COLOR_RED, -1)     # Error
            curses.init_pair(3, curses.COLOR_YELLOW, -1)  # Warning
            curses.init_pair(4, curses.COLOR_CYAN, -1)    # Info
            curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Header
            curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_WHITE) # Selected

        def run(self) -> None:
            """Main application loop."""
            while True:
                choice = self.show_main_menu()

                if choice == 0:  # New extraction
                    self.do_extraction()
                elif choice == 1:  # View saved
                    self.view_saved_certificates()
                elif choice == 2:  # Help
                    self.show_help()
                elif choice == 3:  # Exit
                    break

        def show_main_menu(self) -> int:
            """Display the main menu and return selection."""
            menu_items = [
                "Extract Certificate Chain",
                "View Saved Certificates",
                "Help / Usage",
                "Exit"
            ]
            return self.show_menu("TUI Certificate Extractor", menu_items)

        def show_menu(self, title: str, items: List[str],
                     start_idx: int = 0) -> int:
            """Generic menu display with keyboard navigation."""
            selected = start_idx

            while True:
                self.stdscr.clear()
                height, width = self.stdscr.getmaxyx()

                # Draw header
                self._draw_header(title, width)

                # Draw menu items
                start_y = 4
                for idx, item in enumerate(items):
                    y = start_y + idx
                    if y >= height - 3:
                        break

                    if idx == selected:
                        self.stdscr.attron(curses.color_pair(6))
                        self.stdscr.addstr(y, 2, f" > {item} ".ljust(width - 4))
                        self.stdscr.attroff(curses.color_pair(6))
                    else:
                        self.stdscr.addstr(y, 2, f"   {item}")

                # Draw footer with controls
                footer = "[Up/Down] Navigate  [Enter] Select  [q] Back/Exit"
                self._draw_footer(footer, width, height)

                # Show any message
                if self.message:
                    self._show_message(height, width)

                self.stdscr.refresh()

                # Handle input
                key = self.stdscr.getch()

                if key in [curses.KEY_UP, ord('k')]:
                    selected = (selected - 1) % len(items)
                elif key in [curses.KEY_DOWN, ord('j')]:
                    selected = (selected + 1) % len(items)
                elif key in [curses.KEY_ENTER, 10, 13]:
                    self.message = ""
                    return selected
                elif key in [ord('q'), 27]:  # q or Escape
                    self.message = ""
                    return len(items) - 1  # Return last item (usually exit/back)

        def _draw_header(self, title: str, width: int) -> None:
            """Draw the header bar."""
            self.stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
            self.stdscr.addstr(0, 0, " " * width)
            self.stdscr.addstr(0, 2, f" {title} ")
            self.stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)
            self.stdscr.addstr(2, 2, "-" * (width - 4))

        def _draw_footer(self, text: str, width: int, height: int) -> None:
            """Draw the footer bar."""
            self.stdscr.addstr(height - 2, 2, "-" * (width - 4))
            self.stdscr.attron(curses.color_pair(4))
            self.stdscr.addstr(height - 1, 2, text[:width - 4])
            self.stdscr.attroff(curses.color_pair(4))

        def _show_message(self, height: int, width: int) -> None:
            """Display a status message."""
            color = {
                "success": curses.color_pair(1),
                "error": curses.color_pair(2),
                "warning": curses.color_pair(3),
                "info": curses.color_pair(4)
            }.get(self.message_type, curses.color_pair(4))

            self.stdscr.attron(color)
            msg_line = height - 3
            self.stdscr.addstr(msg_line, 2, self.message[:width - 4])
            self.stdscr.attroff(color)

        def get_input(self, prompt: str, default: str = "") -> str:
            """Get text input from user."""
            self.stdscr.clear()
            height, width = self.stdscr.getmaxyx()

            self._draw_header("Input Required", width)

            self.stdscr.addstr(4, 2, prompt)
            if default:
                self.stdscr.addstr(5, 2, f"(default: {default})")

            self.stdscr.addstr(7, 2, "> ")

            footer = "[Enter] Confirm  [Esc] Cancel"
            self._draw_footer(footer, width, height)

            self.stdscr.refresh()

            # Enable cursor and echo for input
            curses.curs_set(1)
            curses.echo()

            # Get input
            input_win = curses.newwin(1, width - 8, 7, 4)
            input_win.refresh()

            try:
                result = input_win.getstr(0, 0, width - 10).decode('utf-8').strip()
            except KeyboardInterrupt:
                result = ""

            curses.noecho()
            curses.curs_set(0)

            return result if result else default

        def do_extraction(self) -> None:
            """Handle certificate extraction workflow."""
            # Get hostname
            hostname = self.get_input(
                "Enter hostname or IP address:",
                ""
            )

            if not hostname:
                self.message = "Extraction cancelled"
                self.message_type = "warning"
                return

            # Get port
            port_str = self.get_input(
                "Enter port (or press Enter for 443):",
                "443"
            )

            try:
                port = int(port_str)
                if port < 1 or port > 65535:
                    raise ValueError("Invalid port range")
            except ValueError:
                self.message = f"Invalid port: {port_str}"
                self.message_type = "error"
                return

            # Show connecting message
            self.stdscr.clear()
            height, width = self.stdscr.getmaxyx()
            self._draw_header("Connecting...", width)
            self.stdscr.addstr(5, 2, f"Connecting to {hostname}:{port}...")
            self.stdscr.addstr(6, 2, "Please wait...")
            self.stdscr.refresh()

            # Extract certificates
            extractor = CertificateExtractor(hostname, port)
            success = extractor.extract()

            if not success:
                self.message = extractor.error or "Failed to extract certificates"
                self.message_type = "error"
                return

            if not extractor.certificates:
                self.message = "No certificates found"
                self.message_type = "warning"
                return

            self.current_certificates = extractor.certificates
            self.current_hostname = hostname

            # Show success and certificate count
            count = len(self.current_certificates)
            self.message = f"Successfully extracted {count} certificate(s)"
            self.message_type = "success"

            # Show certificate list
            self.show_certificate_list()

        def show_certificate_list(self) -> None:
            """Display extracted certificates with options."""
            while True:
                items = []
                for cert in self.current_certificates:
                    status = "EXPIRED! " if cert.is_expired() else ""
                    items.append(f"{status}{cert.get_display_name()}")

                items.extend([
                    "-" * 30,
                    "Save All Certificates",
                    "Save Selected Certificates",
                    "Back to Main Menu"
                ])

                choice = self.show_menu(
                    f"Certificates from {self.current_hostname}",
                    items
                )

                num_certs = len(self.current_certificates)

                if choice < num_certs:
                    # View certificate details
                    self.show_certificate_details(self.current_certificates[choice])
                elif choice == num_certs + 1:  # Save all
                    self.save_all_certificates()
                elif choice == num_certs + 2:  # Save selected
                    self.save_selected_certificates()
                elif choice == num_certs + 3:  # Back
                    break

        def show_certificate_details(self, cert: CertificateInfo) -> None:
            """Display detailed certificate information."""
            height, width = self.stdscr.getmaxyx()
            lines = cert.format_details(width - 4)

            scroll_pos = 0
            max_scroll = max(0, len(lines) - (height - 6))

            while True:
                self.stdscr.clear()
                self._draw_header(f"Certificate Details [{cert.index}]", width)

                # Draw scrollable content
                visible_lines = height - 6
                for i, line in enumerate(lines[scroll_pos:scroll_pos + visible_lines]):
                    y = 3 + i
                    self.stdscr.addstr(y, 2, line[:width - 4])

                # Show scroll indicator
                if max_scroll > 0:
                    scroll_pct = int((scroll_pos / max_scroll) * 100) if max_scroll else 0
                    self.stdscr.addstr(
                        3, width - 10,
                        f"[{scroll_pct:3d}%]"
                    )

                footer = "[Up/Down] Scroll  [s] Save  [p] Show PEM  [q] Back"
                self._draw_footer(footer, width, height)

                self.stdscr.refresh()

                key = self.stdscr.getch()

                if key in [curses.KEY_UP, ord('k')]:
                    scroll_pos = max(0, scroll_pos - 1)
                elif key in [curses.KEY_DOWN, ord('j')]:
                    scroll_pos = min(max_scroll, scroll_pos + 1)
                elif key == curses.KEY_PPAGE:  # Page Up
                    scroll_pos = max(0, scroll_pos - visible_lines)
                elif key == curses.KEY_NPAGE:  # Page Down
                    scroll_pos = min(max_scroll, scroll_pos + visible_lines)
                elif key == ord('s'):
                    self.save_single_certificate(cert)
                elif key == ord('p'):
                    self.show_pem(cert)
                elif key in [ord('q'), 27]:
                    break

        def show_pem(self, cert: CertificateInfo) -> None:
            """Display the raw PEM content."""
            height, width = self.stdscr.getmaxyx()
            lines = cert.pem.split('\n')

            scroll_pos = 0
            max_scroll = max(0, len(lines) - (height - 6))

            while True:
                self.stdscr.clear()
                self._draw_header("PEM Content", width)

                visible_lines = height - 6
                for i, line in enumerate(lines[scroll_pos:scroll_pos + visible_lines]):
                    y = 3 + i
                    self.stdscr.addstr(y, 2, line[:width - 4])

                footer = "[Up/Down] Scroll  [q] Back"
                self._draw_footer(footer, width, height)

                self.stdscr.refresh()

                key = self.stdscr.getch()

                if key in [curses.KEY_UP, ord('k')]:
                    scroll_pos = max(0, scroll_pos - 1)
                elif key in [curses.KEY_DOWN, ord('j')]:
                    scroll_pos = min(max_scroll, scroll_pos + 1)
                elif key in [ord('q'), 27]:
                    break

        def save_single_certificate(self, cert: CertificateInfo) -> None:
            """Save a single certificate."""
            try:
                path = self.storage.save_certificate(cert, self.current_hostname)
                self.message = f"Saved to: {path}"
                self.message_type = "success"
            except Exception as e:
                self.message = f"Failed to save: {e}"
                self.message_type = "error"

        def save_all_certificates(self) -> None:
            """Save all certificates in the chain."""
            saved = 0
            errors = 0

            for cert in self.current_certificates:
                try:
                    self.storage.save_certificate(cert, self.current_hostname)
                    saved += 1
                except Exception:
                    errors += 1

            if errors:
                self.message = f"Saved {saved}, failed {errors}"
                self.message_type = "warning"
            else:
                self.message = f"Saved all {saved} certificates"
                self.message_type = "success"

        def save_selected_certificates(self) -> None:
            """Let user select which certificates to save."""
            selected = [False] * len(self.current_certificates)
            current_idx = 0

            while True:
                self.stdscr.clear()
                height, width = self.stdscr.getmaxyx()

                self._draw_header("Select Certificates to Save", width)
                self.stdscr.addstr(3, 2, "Use [Space] to toggle selection, [Enter] to save selected")

                for i, cert in enumerate(self.current_certificates):
                    y = 5 + i
                    if y >= height - 3:
                        break

                    mark = "[X]" if selected[i] else "[ ]"
                    name = cert.get_display_name()

                    if i == current_idx:
                        self.stdscr.attron(curses.color_pair(6))
                        self.stdscr.addstr(y, 2, f" {mark} {name} ".ljust(width - 4))
                        self.stdscr.attroff(curses.color_pair(6))
                    else:
                        self.stdscr.addstr(y, 2, f" {mark} {name}")

                footer = "[Space] Toggle  [a] All  [n] None  [Enter] Save  [q] Cancel"
                self._draw_footer(footer, width, height)

                self.stdscr.refresh()

                key = self.stdscr.getch()

                if key in [curses.KEY_UP, ord('k')]:
                    current_idx = (current_idx - 1) % len(self.current_certificates)
                elif key in [curses.KEY_DOWN, ord('j')]:
                    current_idx = (current_idx + 1) % len(self.current_certificates)
                elif key == ord(' '):
                    selected[current_idx] = not selected[current_idx]
                elif key == ord('a'):
                    selected = [True] * len(self.current_certificates)
                elif key == ord('n'):
                    selected = [False] * len(self.current_certificates)
                elif key in [curses.KEY_ENTER, 10, 13]:
                    # Save selected certificates
                    saved = 0
                    for i, cert in enumerate(self.current_certificates):
                        if selected[i]:
                            try:
                                self.storage.save_certificate(cert, self.current_hostname)
                                saved += 1
                            except Exception:
                                pass

                    self.message = f"Saved {saved} certificate(s)"
                    self.message_type = "success"
                    break
                elif key in [ord('q'), 27]:
                    break

        def view_saved_certificates(self) -> None:
            """View and manage saved certificates."""
            while True:
                saved = self.storage.list_saved_certificates()

                if not saved:
                    self.message = f"No saved certificates in {self.storage.base_dir}"
                    self.message_type = "info"
                    return

                items = [name for name, _ in saved]
                items.append("Back to Main Menu")

                choice = self.show_menu("Saved Certificates", items)

                if choice < len(saved):
                    name, path = saved[choice]
                    self.view_saved_certificate(name, path)
                else:
                    break

        def view_saved_certificate(self, name: str, path: Path) -> None:
            """View a single saved certificate."""
            cert = self.storage.read_certificate(path)

            if not cert:
                self.message = f"Failed to read certificate: {path}"
                self.message_type = "error"
                return

            height, width = self.stdscr.getmaxyx()
            lines = cert.format_details(width - 4)

            scroll_pos = 0
            max_scroll = max(0, len(lines) - (height - 6))

            while True:
                self.stdscr.clear()
                self._draw_header(f"Saved: {name}", width)

                visible_lines = height - 6
                for i, line in enumerate(lines[scroll_pos:scroll_pos + visible_lines]):
                    y = 3 + i
                    self.stdscr.addstr(y, 2, line[:width - 4])

                footer = "[Up/Down] Scroll  [d] Delete  [p] Show PEM  [q] Back"
                self._draw_footer(footer, width, height)

                self.stdscr.refresh()

                key = self.stdscr.getch()

                if key in [curses.KEY_UP, ord('k')]:
                    scroll_pos = max(0, scroll_pos - 1)
                elif key in [curses.KEY_DOWN, ord('j')]:
                    scroll_pos = min(max_scroll, scroll_pos + 1)
                elif key == ord('d'):
                    if self.confirm_action("Delete this certificate?"):
                        if self.storage.delete_certificate(path):
                            self.message = "Certificate deleted"
                            self.message_type = "success"
                            break
                        else:
                            self.message = "Failed to delete"
                            self.message_type = "error"
                elif key == ord('p'):
                    self.show_pem(cert)
                elif key in [ord('q'), 27]:
                    break

        def confirm_action(self, message: str) -> bool:
            """Show a confirmation dialog."""
            items = ["Yes", "No"]
            choice = self.show_menu(message, items)
            return choice == 0

        def show_help(self) -> None:
            """Display help information."""
            help_text = [
                "TUI Certificate Extractor - Help",
                "=" * 40,
                "",
                "OVERVIEW",
                "--------",
                "This tool extracts TLS/SSL certificate chains from",
                "remote servers and allows you to save them as PEM files.",
                "",
                "MAIN MENU OPTIONS",
                "-----------------",
                "",
                "1. Extract Certificate Chain",
                "   - Enter a hostname (e.g., google.com) or IP address",
                "   - Optionally specify a port (default: 443)",
                "   - View the full certificate chain",
                "   - Save individual or all certificates",
                "",
                "2. View Saved Certificates",
                "   - Browse previously saved certificates",
                "   - View certificate details",
                "   - Delete unwanted certificates",
                "",
                "3. Help / Usage",
                "   - This help screen",
                "",
                "4. Exit",
                "   - Exit the application",
                "",
                "KEYBOARD SHORTCUTS",
                "------------------",
                "  Up/Down or j/k  - Navigate menu items",
                "  Enter           - Select / Confirm",
                "  q or Esc        - Go back / Cancel",
                "  Space           - Toggle selection (in selection mode)",
                "  s               - Save certificate (when viewing)",
                "  p               - Show PEM content",
                "  d               - Delete certificate (when viewing saved)",
                "  a               - Select all (in selection mode)",
                "  n               - Select none (in selection mode)",
                "",
                "CERTIFICATE STORAGE",
                "-------------------",
                f"Certificates are saved to: {self.storage.base_dir}",
                "Each host gets its own subdirectory.",
                "",
                "REQUIREMENTS",
                "------------",
                "- Python 3.6+",
                "- OpenSSL command-line tool (recommended)",
                "  Without OpenSSL, only the leaf certificate is extracted.",
                "",
                "Press q or Esc to return to main menu..."
            ]

            height, width = self.stdscr.getmaxyx()
            scroll_pos = 0
            max_scroll = max(0, len(help_text) - (height - 5))

            while True:
                self.stdscr.clear()
                self._draw_header("Help", width)

                visible_lines = height - 5
                for i, line in enumerate(help_text[scroll_pos:scroll_pos + visible_lines]):
                    y = 3 + i
                    self.stdscr.addstr(y, 2, line[:width - 4])

                footer = "[Up/Down] Scroll  [q] Back"
                self._draw_footer(footer, width, height)

                self.stdscr.refresh()

                key = self.stdscr.getch()

                if key in [curses.KEY_UP, ord('k')]:
                    scroll_pos = max(0, scroll_pos - 1)
                elif key in [curses.KEY_DOWN, ord('j')]:
                    scroll_pos = min(max_scroll, scroll_pos + 1)
                elif key in [ord('q'), 27]:
                    break


    def run_tui() -> None:
        """Initialize and run the curses TUI application."""
        def main(stdscr):
            app = TUIApp(stdscr)
            app.run()

        curses.wrapper(main)


# ============================================================================
# Simple Text Interface (Fallback for Windows without curses)
# ============================================================================

class SimpleTextInterface:
    """Fallback text-based interface when curses is not available."""

    def __init__(self):
        self.storage = CertificateStorage()

    def run(self) -> None:
        """Main application loop."""
        self.clear_screen()
        print("=" * 60)
        print(" TUI Certificate Extractor (Simple Mode) ".center(60))
        print("=" * 60)
        print()

        while True:
            print("\nMain Menu:")
            print("  1. Extract Certificate Chain")
            print("  2. View Saved Certificates")
            print("  3. Help")
            print("  4. Exit")
            print()

            choice = input("Enter choice (1-4): ").strip()

            if choice == "1":
                self.do_extraction()
            elif choice == "2":
                self.view_saved()
            elif choice == "3":
                self.show_help()
            elif choice == "4":
                print("\nGoodbye!")
                break
            else:
                print("Invalid choice. Please try again.")

    def clear_screen(self) -> None:
        """Clear the terminal screen using ANSI escape codes."""
        # Use ANSI escape codes instead of os.system for safety
        print("\033[2J\033[H", end="")

    def do_extraction(self) -> None:
        """Extract certificates from a host."""
        print("\n--- Extract Certificate Chain ---\n")

        hostname = input("Enter hostname or IP: ").strip()
        if not hostname:
            print("Cancelled.")
            return

        port_str = input("Enter port (default 443): ").strip() or "443"

        try:
            port = int(port_str)
        except ValueError:
            print(f"Invalid port: {port_str}")
            return

        print(f"\nConnecting to {hostname}:{port}...")

        extractor = CertificateExtractor(hostname, port)
        success = extractor.extract()

        if not success:
            print(f"Error: {extractor.error}")
            return

        if not extractor.certificates:
            print("No certificates found.")
            return

        print(f"\nFound {len(extractor.certificates)} certificate(s):\n")

        for cert in extractor.certificates:
            print(f"  [{cert.index}] {cert.get_common_name()}")
            print(f"      Issuer: {cert.get_issuer_cn()}")
            print(f"      Valid: {cert.not_before} to {cert.not_after}")
            print()

        # Save option
        save = input("Save certificates? (y/n/index): ").strip().lower()

        if save == 'y':
            for cert in extractor.certificates:
                path = self.storage.save_certificate(cert, hostname)
                print(f"  Saved: {path}")
        elif save.isdigit():
            idx = int(save)
            if 0 <= idx < len(extractor.certificates):
                path = self.storage.save_certificate(
                    extractor.certificates[idx], hostname
                )
                print(f"  Saved: {path}")
            else:
                print("Invalid index.")

    def view_saved(self) -> None:
        """View saved certificates."""
        saved = self.storage.list_saved_certificates()

        if not saved:
            print(f"\nNo saved certificates in {self.storage.base_dir}")
            return

        print("\n--- Saved Certificates ---\n")

        for i, (name, path) in enumerate(saved):
            print(f"  [{i}] {name}")

        choice = input("\nEnter index to view (or press Enter to go back): ").strip()

        if choice.isdigit():
            idx = int(choice)
            if 0 <= idx < len(saved):
                name, path = saved[idx]
                cert = self.storage.read_certificate(path)
                if cert:
                    for line in cert.format_details(60):
                        print(line)

    def show_help(self) -> None:
        """Display help information."""
        print("""
--- Help ---

This tool extracts TLS/SSL certificate chains from remote servers.

Usage:
  1. Select "Extract Certificate Chain"
  2. Enter a hostname (e.g., google.com) or IP address
  3. Enter the port (default 443 for HTTPS)
  4. View the certificate chain
  5. Choose to save all or specific certificates

Saved certificates are stored in: {}

Requirements:
  - Python 3.6+
  - OpenSSL (recommended for full chain extraction)

For the full TUI experience on Windows, install windows-curses:
  pip install windows-curses
""".format(self.storage.base_dir))


# ============================================================================
# Entry Point
# ============================================================================

def main() -> None:
    """Main entry point for the application."""
    # Check Python version
    if sys.version_info < (3, 6):
        print("Error: Python 3.6 or higher is required.")
        sys.exit(1)

    # Parse simple command-line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] in ['-h', '--help']:
            print(__doc__)
            sys.exit(0)
        elif sys.argv[1] == '--simple':
            # Force simple text interface
            app = SimpleTextInterface()
            app.run()
            return
        elif sys.argv[1] == '--version':
            print("TUI Certificate Extractor v1.0.0")
            sys.exit(0)

    # Run appropriate interface
    if CURSES_AVAILABLE:
        try:
            run_tui()
        except Exception as e:
            print(f"TUI error: {e}")
            print("Falling back to simple text interface...")
            app = SimpleTextInterface()
            app.run()
    else:
        app = SimpleTextInterface()
        app.run()


if __name__ == "__main__":
    main()
