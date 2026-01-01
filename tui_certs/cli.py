import argparse
from pathlib import Path
from .core.extractor import CertificateExtractor
from .core.storage import CertificateStorage


class SimpleTextInterface:
    def __init__(self):
        self.storage = CertificateStorage()

    def run(self) -> None:
        print("--- TUI Certificate Extractor (Simple Mode) ---")
        while True:
            print("\n1. Extract\n2. View Saved\n3. Exit")
            choice = input("Choice: ").strip()
            if choice == "1":
                self.do_extraction()
            elif choice == "2":
                self.view_saved()
            elif choice == "3":
                break

    def do_extraction(self) -> None:
        host = input("Host: ").strip()
        if not host:
            return
        extractor = CertificateExtractor(host)
        if extractor.extract():
            for cert in extractor.certificates:
                print(
                    f"[{cert.index}] {cert.get_common_name()} - {cert.get_validity_status()}"
                )
            save = input("Save all? (y/n): ").strip().lower()
            if save == "y":
                for cert in extractor.certificates:
                    self.storage.save_certificate(cert, host)
        else:
            print(f"Error: {extractor.error}")

    def view_saved(self) -> None:
        saved = self.storage.list_saved_certificates()
        for i, (name, _) in enumerate(saved):
            print(f"[{i}] {name}")


def batch_process(file_path: str) -> None:
    path = Path(file_path)
    if not path.exists():
        print(f"File not found: {file_path}")
        return

    storage = CertificateStorage()
    with open(path, "r") as f:
        hosts = [line.strip() for line in f if line.strip()]

    for host in hosts:
        print(f"Processing {host}...")
        extractor = CertificateExtractor(host)
        if extractor.extract():
            print(f"  Found {len(extractor.certificates)} certificates")
            for cert in extractor.certificates:
                storage.save_certificate(cert, host)
            # Auto-export JSON for batch
            json_path = storage.base_dir / f"{host}_batch.json"
            storage.export_json(extractor.certificates, host, json_path)
        else:
            print(f"  Error: {extractor.error}")


def main():
    parser = argparse.ArgumentParser(description="TUI Certificate Extractor")
    parser.add_argument(
        "--simple", action="store_true", help="Force simple text interface"
    )
    parser.add_argument("--batch", type=str, help="Batch process hosts from file")
    parser.add_argument("--version", action="store_true", help="Show version")
    args = parser.parse_args()

    if args.version:
        print("TUI Certificate Extractor v1.1.0")
        return

    if args.batch:
        batch_process(args.batch)
        return

    if args.simple:
        SimpleTextInterface().run()
        return

    # Try TUI
    try:
        from .tui import run_tui

        run_tui()
    except Exception as e:
        print(f"TUI error: {e}")
        SimpleTextInterface().run()


if __name__ == "__main__":
    main()
