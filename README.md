# rscert

A Rust implementation of fastcert - a simple zero-config tool for making locally-trusted development certificates.

## Overview

rscert is a command-line tool that makes it easy to create and manage locally-trusted development certificates. It works by creating a local certificate authority (CA) and then generating certificates signed by that CA. The CA certificate is installed in your system's trust store, making all certificates it signs trusted by your browsers and development tools.

## Features

- Zero configuration required - works out of the box
- Automatically creates and manages a local CA
- Generates certificates for multiple domains and IP addresses
- Supports wildcard certificates
- ECDSA and RSA key support
- Client certificate generation
- PKCS#12 format support
- Cross-platform support (macOS, Linux, Windows)
- Integrates with system trust stores
- Firefox and Java trust store support

## Installation

### From Source

1. Clone the repository:
```bash
git clone https://github.com/yourusername/rscert.git
cd rscert
```

2. Build and install:
```bash
cargo install --path .
```

This will install the `rscert` binary to your cargo bin directory (usually `~/.cargo/bin`).

### Build from Source

For development or custom builds:

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# The binary will be in target/release/rscert
```

### Prerequisites

- Rust 1.70 or later
- Cargo package manager
- Administrator/root privileges for installing CA certificates

### Platform-Specific Requirements

**macOS:**
- No additional dependencies required
- System trust store integration works out of the box

**Linux:**
- For Firefox/Chrome support: `certutil` (NSS tools)
  ```bash
  # Debian/Ubuntu
  sudo apt install libnss3-tools

  # Fedora/RHEL
  sudo dnf install nss-tools

  # Arch Linux
  sudo pacman -S nss
  ```

**Windows:**
- Administrator privileges required for system trust store installation
- No additional dependencies needed

## Quick Start

```bash
# Install local CA in system trust store
rscert -install

# Generate certificate for a domain
rscert example.com

# Generate certificate for multiple domains and IPs
rscert example.com localhost 127.0.0.1 ::1

# Generate wildcard certificate
rscert "*.example.com"
```

## Usage Examples

### Basic Certificate Generation

Generate a certificate for a single domain:
```bash
rscert example.com
```

This creates two files:
- `example.com.pem` - the certificate
- `example.com-key.pem` - the private key

### Multiple Domains

Generate a certificate valid for multiple domains and IP addresses:
```bash
rscert example.com localhost 127.0.0.1 ::1
```

The files will be named `example.com+3.pem` and `example.com+3-key.pem` (the +3 indicates 3 additional names beyond the first).

### Wildcard Certificates

Generate a wildcard certificate:
```bash
rscert "*.example.com"
```

Creates `_wildcard.example.com.pem` and `_wildcard.example.com-key.pem`.

### Custom File Names

Specify custom output file names:
```bash
rscert --cert-file mycert.pem --key-file mykey.pem example.com
```

### ECDSA Keys

Generate a certificate with an ECDSA key instead of RSA:
```bash
rscert --ecdsa example.com
```

ECDSA keys are smaller and faster than RSA keys.

### Client Certificates

Generate a certificate for client authentication:
```bash
rscert --client client.example.com
```

### PKCS12 Format

Generate a PKCS12 file (.pfx) containing both certificate and key:
```bash
rscert --pkcs12 example.com
```

Or specify a custom PKCS12 file path:
```bash
rscert --p12-file mycert.pfx example.com
```

### Certificate Signing Requests

Generate a certificate from an existing CSR:
```bash
rscert --csr mycsr.pem --cert-file mycert.pem
```

### Managing the CA

View the CA certificate location:
```bash
rscert -CAROOT
```

Install the CA in system trust stores:
```bash
rscert -install
```

Uninstall the CA from system trust stores (but keep the certificate):
```bash
rscert -uninstall
```

### Environment Variables

Set a custom CA location:
```bash
export CAROOT="$HOME/my-ca"
rscert -install
```

Specify which trust stores to use:
```bash
export TRUST_STORES="system,firefox,java"
rscert -install
```

## Platform Support

- macOS 10.12+
- Linux (with certutil for Firefox/Chrome, or manual installation)
- Windows 7+ (with administrator privileges for system-wide installation)

## How It Works

When you run `rscert -install`, it creates a new local certificate authority and installs it in your system trust store. When you generate certificates, they are signed by this local CA, making them trusted by your system.

The CA certificate and key are stored in:
- macOS/Linux: `$HOME/.local/share/rscert`
- Windows: `%LOCALAPPDATA%\rscert`

You can override this location by setting the `CAROOT` environment variable.

## Security

The CA key is the most sensitive file. Keep it secure and never share it. If you suspect it has been compromised, you should uninstall the CA and delete the CAROOT directory.

## License

MIT License - see LICENSE file for details

## Status

Active development - core functionality implemented
