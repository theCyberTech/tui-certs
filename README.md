# TUI Certificate Extractor

**A command-line Text User Interface for extracting, viewing, and saving TLS certificate chains from remote servers.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](https://github.com/yourusername/tui-certs)

---

## Description

TUI Certificate Extractor is a lightweight, terminal-based tool that simplifies the process of retrieving and analyzing TLS/SSL certificate chains from any remote server. Whether you're a security professional auditing certificate configurations, a developer debugging HTTPS issues, or a sysadmin managing certificate deployments, this tool provides a fast, intuitive interface for inspecting the complete certificate chain without leaving your terminal.

Built entirely with Python's standard library, it requires no external dependencies and works seamlessly across Linux, macOS, and Windows platforms.

---

## Table of Contents

- [Features](#features)
- [Screenshots](#screenshots)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

---

## Features

- **Full Certificate Chain Extraction** - Retrieve the complete chain including leaf certificate and all intermediate CA certificates
- **Interactive TUI** - Navigate with keyboard shortcuts using a polished curses-based interface
- **Detailed Certificate Analysis** - View subject, issuer, validity dates, serial number, signature algorithm, SANs, and more
- **Expiration Detection** - Quickly identify expired certificates with visual indicators
- **Selective Saving** - Save individual certificates or the entire chain as PEM-encoded files
- **Certificate Management** - Browse, view, and delete previously saved certificates
- **Cross-Platform Support** - Works on Linux, macOS, and Windows (with fallback text interface)
- **SNI Support** - Proper Server Name Indication for virtual hosting environments
- **Zero Dependencies** - Uses only Python standard library modules
- **Fallback Mode** - Graceful degradation to simple text interface when curses is unavailable

---

## Screenshots

### Main Menu
```
┌────────────────────────────────────────────────────────────────┐
│  TUI Certificate Extractor                                     │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│   > Extract Certificate Chain                                  │
│     View Saved Certificates                                    │
│     Help / Usage                                               │
│     Exit                                                       │
│                                                                │
├────────────────────────────────────────────────────────────────┤
│  [Up/Down] Navigate  [Enter] Select  [q] Back/Exit             │
└────────────────────────────────────────────────────────────────┘
```

### Certificate Details View
```
================================================================================
                            Certificate [0]
================================================================================

Subject:
  commonName: example.com
  organizationName: Example Inc

Issuer:
  commonName: DigiCert TLS RSA SHA256 2020 CA1
  organizationName: DigiCert Inc

Validity:
  Not Before: Jan 15 00:00:00 2024 GMT
  Not After:  Jan 15 23:59:59 2025 GMT
  Status:     Valid

Technical Details:
  Serial Number: 0A1B2C3D4E5F...
  Version: 3
  Signature Algorithm: sha256WithRSAEncryption
  Is CA: False
```

---

## Prerequisites

- **Python 3.6+** - The application requires Python 3.6 or later
- **OpenSSL** (recommended) - For full certificate chain extraction
  - Without OpenSSL, only the leaf certificate can be retrieved
  - Most Linux and macOS systems have OpenSSL pre-installed
  - Windows users can install OpenSSL via [Chocolatey](https://chocolatey.org/): `choco install openssl`
- **windows-curses** (Windows only, optional) - For the full TUI experience
  ```bash
  pip install windows-curses
  ```

---

## Installation

### Quick Start

1. **Clone or download** the repository:
   ```bash
   git clone https://github.com/yourusername/tui-certs.git
   cd tui-certs
   ```

2. **Run the application** directly (no installation required):
   ```bash
   python3 tui_certs.py
   ```

### Make Executable (Linux/macOS)

```bash
chmod +x tui_certs.py
./tui_certs.py
```

### Verify OpenSSL (optional but recommended)

```bash
openssl version
# Should output something like: OpenSSL 3.x.x
```

---

## Usage

### Interactive Mode

Launch the application without arguments for the full interactive TUI:

```bash
python3 tui_certs.py
```

### Command-Line Options

```bash
# Display help and documentation
python3 tui_certs.py --help
python3 tui_certs.py -h

# Show version information
python3 tui_certs.py --version

# Force simple text interface (no curses)
python3 tui_certs.py --simple
```

### Keyboard Navigation

| Key | Action |
|-----|--------|
| `Up` / `k` | Move selection up |
| `Down` / `j` | Move selection down |
| `Enter` | Select / Confirm |
| `q` / `Esc` | Go back / Cancel |
| `Space` | Toggle selection (in multi-select mode) |
| `s` | Save current certificate |
| `p` | Show PEM content |
| `d` | Delete saved certificate |
| `a` | Select all |
| `n` | Select none |
| `PgUp` / `PgDn` | Scroll pages |

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

| Platform | Default Path |
|----------|--------------|
| Linux/macOS | `~/.tui_certs/` |
| Windows | `C:\Users\<username>\.tui_certs\` |

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
