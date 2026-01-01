# TUI Certificate Extractor

**A command-line Text User Interface for extracting, viewing, and saving TLS certificate chains from remote servers.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](https://github.com/yourusername/tui-certs)

---

## Description

TUI Certificate Extractor is a lightweight, terminal-based tool that simplifies the process of retrieving and analyzing TLS/SSL certificate chains from any remote server. It features a modular architecture, robust certificate parsing using the `cryptography` library, and a polished interactive TUI.

---

## Features

- **Full Certificate Chain Extraction** - Retrieve the complete chain including leaf certificate and all intermediate CA certificates.
- **Interactive TUI** - Navigate with keyboard shortcuts using a polished curses-based interface.
- **Detailed Certificate Analysis** - View subject, issuer, validity dates, serial number, signature algorithm, SANs, and more.
- **Expiration Detection** - Quickly identify expired certificates with visual indicators and color-coded warnings.
- **Selective Saving** - Save individual certificates or the entire chain as PEM-encoded files.
- **JSON Export** - Export certificate details to JSON format for automated processing.
- **Batch Processing** - Process multiple hostnames from a file and automatically save/export results.
- **Cross-Platform Support** - Works on Linux, macOS, and Windows (with fallback text interface).
- **Zero Configuration** - Sensible defaults that work out of the box.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Development](#development)
- [License](#license)

---

## Installation

### From Source

```bash
git clone https://github.com/yourusername/tui-certs.git
cd tui-certs
pip install .
```

## Usage

### Interactive TUI

Launch the full interactive interface:

```bash
tui-certs
```

### Batch Processing

Extract certificates for a list of hosts:

```bash
tui-certs --batch hosts.txt
```

### Simple Mode

Force the simple text-based interface:

```bash
tui-certs --simple
```

### Command-Line Options

| Option           | Description                             |
| ---------------- | --------------------------------------- |
| `--batch <file>` | Process hostnames from a text file      |
| `--simple`       | Force simple text interface (no curses) |
| `--version`      | Show version information                |
| `--help`         | Show help message                       |

### Keyboard Navigation

| Key          | Action                             |
| ------------ | ---------------------------------- |
| `Up` / `k`   | Move selection up                  |
| `Down` / `j` | Move selection down                |
| `Enter`      | Select / Confirm                   |
| `q` / `Esc`  | Go back / Cancel                   |
| `s`          | Save current certificate           |
| `p`          | Show PEM content                   |
| `j`          | Export chain to JSON (when in TUI) |

---

## Development

### Prerequisites

- Python 3.6+
- `cryptography` library (installed automatically via `pip install .`)

### Running Tests

```bash
pytest tests/
```

### Project Structure

- `tui_certs/core/`: Business logic (models, extractor, storage)
- `tui_certs/tui.py`: Curses-based interface
- `tui_certs/cli.py`: CLI entry point and simple interface

### Example Workflow

1. **Start the application** and select "Extract Certificate Chain"
2. **Enter hostname**: `github.com`
3. **Enter port** (press Enter for default 443)
4. **Browse the certificate chain** - Click on any certificate to view details
5. **Save certificates** - Choose "Save All" or "Save Selected"
6. **View later** - Use "View Saved Certificates" from the main menu

---

## Configuration

### Certificate Storage Location

By default, certificates are saved to:

| Platform    | Default Path                      |
| ----------- | --------------------------------- |
| Linux/macOS | `~/.tui_certs/`                   |
| Windows     | `C:\Users\<username>\.tui_certs\` |

Certificates are organized in subdirectories by hostname:

```
~/.tui_certs/
├── github_com/
│   ├── github_com_20240115_143022.pem
│   └── DigiCert_SHA2_High_Assurance_Server_CA_20240115_143022.pem
└── google_com/
    └── google_com_20240116_091500.pem
```

### Connection Settings

- **Default Port**: 443 (HTTPS)
- **Connection Timeout**: 10 seconds
- **SNI**: Enabled by default

---

## Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Maintain compatibility with Python 3.6+
- Keep dependencies to standard library only
- Add docstrings for new functions/classes
- Test on multiple platforms when possible

### Reporting Issues

Please include:

- Python version (`python3 --version`)
- Operating system and version
- OpenSSL version (`openssl version`)
- Steps to reproduce the issue
- Expected vs actual behavior

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 TUI Certificate Extractor

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## Acknowledgments

- Built with Python's excellent `ssl`, `socket`, and `curses` modules
- Inspired by the need for a simple, portable certificate inspection tool
- Thanks to the OpenSSL project for comprehensive certificate parsing capabilities
