import curses
from typing import List
from .core.models import CertificateInfo
from .core.extractor import CertificateExtractor
from .core.storage import CertificateStorage


class TUIApp:
    """Main TUI application using curses."""

    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.storage = CertificateStorage()
        self.current_certificates: List[CertificateInfo] = []
        self.current_hostname: str = ""
        self.message: str = ""
        self.message_type: str = "info"  # info, success, error, warning

        # Initialize curses settings
        curses.curs_set(0)
        curses.start_color()
        curses.use_default_colors()

        # Define color pairs
        curses.init_pair(1, curses.COLOR_GREEN, -1)  # Success
        curses.init_pair(2, curses.COLOR_RED, -1)  # Error
        curses.init_pair(3, curses.COLOR_YELLOW, -1)  # Warning
        curses.init_pair(4, curses.COLOR_CYAN, -1)  # Info
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Header
        curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_WHITE)  # Selected

    def run(self) -> None:
        while True:
            choice = self.show_main_menu()
            if choice == 0:
                self.do_extraction()
            elif choice == 1:
                self.view_saved_certificates()
            elif choice == 2:
                self.show_help()
            elif choice == 3:
                break

    def show_main_menu(self) -> int:
        menu_items = [
            "Extract Certificate Chain",
            "View Saved Certificates",
            "Help / Usage",
            "Exit",
        ]
        return self.show_menu("TUI Certificate Extractor", menu_items)

    def show_menu(self, title: str, items: List[str], start_idx: int = 0) -> int:
        selected = start_idx
        while True:
            self.stdscr.clear()
            height, width = self.stdscr.getmaxyx()
            self._draw_header(title, width)

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

            self._draw_footer(
                "[Up/Down] Navigate  [Enter] Select  [q] Back/Exit", width, height
            )
            if self.message:
                self._show_message(height, width)
            self.stdscr.refresh()

            key = self.stdscr.getch()
            if key in [curses.KEY_UP, ord("k")]:
                selected = (selected - 1) % len(items)
            elif key in [curses.KEY_DOWN, ord("j")]:
                selected = (selected + 1) % len(items)
            elif key in [curses.KEY_ENTER, 10, 13]:
                self.message = ""
                return selected
            elif key in [ord("q"), 27]:
                self.message = ""
                return len(items) - 1

    def _draw_header(self, title: str, width: int) -> None:
        self.stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
        self.stdscr.addstr(0, 0, " " * width)
        self.stdscr.addstr(0, 2, f" {title} ")
        self.stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)
        self.stdscr.addstr(2, 2, "-" * (width - 4))

    def _draw_footer(self, text: str, width: int, height: int) -> None:
        self.stdscr.addstr(height - 2, 2, "-" * (width - 4))
        self.stdscr.attron(curses.color_pair(4))
        self.stdscr.addstr(height - 1, 2, text[: width - 4])
        self.stdscr.attroff(curses.color_pair(4))

    def _show_message(self, height: int, width: int) -> None:
        color = {
            "success": curses.color_pair(1),
            "error": curses.color_pair(2),
            "warning": curses.color_pair(3),
            "info": curses.color_pair(4),
        }.get(self.message_type, curses.color_pair(4))
        self.stdscr.attron(color)
        self.stdscr.addstr(height - 3, 2, self.message[: width - 4])
        self.stdscr.attroff(color)

    def get_input(self, prompt: str, default: str = "") -> str:
        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()
        self._draw_header("Input Required", width)
        self.stdscr.addstr(4, 2, prompt)
        if default:
            self.stdscr.addstr(5, 2, f"(default: {default})")
        self.stdscr.addstr(7, 2, "> ")
        self._draw_footer("[Enter] Confirm  [Esc] Cancel", width, height)
        self.stdscr.refresh()
        curses.curs_set(1)
        curses.echo()
        input_win = curses.newwin(1, width - 8, 7, 4)
        input_win.refresh()
        try:
            result = input_win.getstr(0, 0, width - 10).decode("utf-8").strip()
        except KeyboardInterrupt:
            result = ""
        curses.noecho()
        curses.curs_set(0)
        return result if result else default

    def do_extraction(self) -> None:
        hostname = self.get_input("Enter hostname or IP address:", "")
        if not hostname:
            return
        port_str = self.get_input("Enter port (or press Enter for 443):", "443")
        try:
            port = int(port_str)
        except ValueError:
            self.message = f"Invalid port: {port_str}"
            self.message_type = "error"
            return

        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()
        self._draw_header("Connecting...", width)
        self.stdscr.addstr(5, 2, f"Connecting to {hostname}:{port}...")
        self.stdscr.refresh()

        extractor = CertificateExtractor(hostname, port)
        if extractor.extract():
            self.current_certificates = extractor.certificates
            self.current_hostname = hostname
            self.message = f"Extracted {len(self.current_certificates)} certificates"
            self.message_type = "success"
            self.show_certificate_list()
        else:
            self.message = extractor.error or "Extraction failed"
            self.message_type = "error"

    def show_certificate_list(self) -> None:
        while True:
            items = []
            for cert in self.current_certificates:
                status = "[EXPIRED] " if cert.is_expired() else ""
                items.append(f"{status}{cert.get_common_name()}")

            items.extend(["-" * 30, "Save All", "Export JSON", "Back"])
            choice = self.show_menu(f"Certificates from {self.current_hostname}", items)
            num_certs = len(self.current_certificates)

            if choice < num_certs:
                self.show_certificate_details(self.current_certificates[choice])
            elif choice == num_certs + 1:
                self.save_all()
            elif choice == num_certs + 2:
                self.export_json()
            elif choice == num_certs + 3:
                break

    def show_certificate_details(self, cert: CertificateInfo) -> None:
        height, width = self.stdscr.getmaxyx()
        # Basic details for display
        details = [
            f"Subject: {cert.get_common_name()}",
            f"Issuer:  {cert.get_issuer_cn()}",
            f"Valid:   {cert.not_before} to {cert.not_after}",
            f"Status:  {cert.get_validity_status()}",
            f"Serial:  {cert.serial_number}",
            f"Algo:    {cert.signature_algorithm}",
            f"Is CA:   {cert.is_ca}",
            "SANs:",
        ] + [f"  - {s}" for s in cert.san[:10]]

        scroll_pos = 0
        max_scroll = max(0, len(details) - (height - 6))

        while True:
            self.stdscr.clear()
            self._draw_header(f"Details [{cert.index}]", width)
            visible = height - 6
            for i, line in enumerate(details[scroll_pos : scroll_pos + visible]):
                if "EXPIRED" in line:
                    self.stdscr.attron(curses.color_pair(2))
                    self.stdscr.addstr(3 + i, 2, line[: width - 4])
                    self.stdscr.attroff(curses.color_pair(2))
                else:
                    self.stdscr.addstr(3 + i, 2, line[: width - 4])

            self._draw_footer(
                "[Up/Down] Scroll  [s] Save  [p] PEM  [q] Back", width, height
            )
            self.stdscr.refresh()
            key = self.stdscr.getch()
            if key in [curses.KEY_UP, ord("k")]:
                scroll_pos = max(0, scroll_pos - 1)
            elif key in [curses.KEY_DOWN, ord("j")]:
                scroll_pos = min(max_scroll, scroll_pos + 1)
            elif key == ord("s"):
                self.storage.save_certificate(cert, self.current_hostname)
                self.message = "Saved certificate"
                self.message_type = "success"
                break
            elif key == ord("p"):
                self.show_pem(cert)
            elif key in [ord("q"), 27]:
                break

    def show_pem(self, cert: CertificateInfo) -> None:
        height, width = self.stdscr.getmaxyx()
        lines = cert.pem.split("\n")
        scroll_pos = 0
        max_scroll = max(0, len(lines) - (height - 6))
        while True:
            self.stdscr.clear()
            self._draw_header("PEM Content", width)
            for i, line in enumerate(lines[scroll_pos : scroll_pos + height - 6]):
                self.stdscr.addstr(3 + i, 2, line[: width - 4])
            self._draw_footer("[Up/Down] Scroll  [q] Back", width, height)
            self.stdscr.refresh()
            key = self.stdscr.getch()
            if key in [curses.KEY_UP, ord("k")]:
                scroll_pos = max(0, scroll_pos - 1)
            elif key in [curses.KEY_DOWN, ord("j")]:
                scroll_pos = min(max_scroll, scroll_pos + 1)
            elif key in [ord("q"), 27]:
                break

    def save_all(self) -> None:
        for cert in self.current_certificates:
            self.storage.save_certificate(cert, self.current_hostname)
        self.message = f"Saved all {len(self.current_certificates)} certificates"
        self.message_type = "success"

    def export_json(self) -> None:
        timestamp = (
            CertificateInfo(self.current_certificates[0].pem).not_before.strftime(
                "%Y%m%d"
            )
            if self.current_certificates
            else "export"
        )
        filename = f"{self.current_hostname}_{timestamp}.json"
        path = self.storage.base_dir / filename
        self.storage.export_json(self.current_certificates, self.current_hostname, path)
        self.message = f"Exported to {path}"
        self.message_type = "success"

    def view_saved_certificates(self) -> None:
        saved = self.storage.list_saved_certificates()
        if not saved:
            self.message = "No saved certificates"
            self.message_type = "info"
            return
        items = [s[0] for s in saved] + ["Back"]
        choice = self.show_menu("Saved Certificates", items)
        if choice < len(saved):
            cert = self.storage.read_certificate(saved[choice][1])
            if cert:
                self.show_certificate_details(cert)

    def show_help(self) -> None:
        # Simplified help
        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()
        self._draw_header("Help", width)
        self.stdscr.addstr(4, 2, "Use Up/Down to navigate menus.")
        self.stdscr.addstr(5, 2, "Press Enter to select.")
        self.stdscr.addstr(6, 2, "Press q to go back.")
        self._draw_footer("Press any key to return", width, height)
        self.stdscr.getch()


def run_tui():
    curses.wrapper(lambda stdscr: TUIApp(stdscr).run())
