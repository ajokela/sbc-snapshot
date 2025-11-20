# SBC Snapshot - Security & Exposure Snapshot Tool

A security and configuration assessment tool for Single Board Computers (SBCs) written in Rust. Designed to help you quickly understand what you've inherited when you SSH into a freshly-flashed SBC image.

## Overview

Many SBC vendor images ship with concerning default configurations:
- Default usernames and passwords (e.g., `pi/raspberry`, `root/1234`)
- SSH password authentication enabled
- Root login permitted
- Unnecessary services running
- No firewall configured

**SBC Snapshot** provides a quick, comprehensive security assessment of your SBC's current state.

## Features

- **Fully Static Binary**: Zero dependencies! Download and run immediately - no libraries needed
- **Tiny**: ~1.7MB binary that includes everything
- **Cross-Platform**: ARM64, ARMv7, and x86_64 builds available
- **Modular Architecture**: 9 specialized analyzers covering all security domains
- **Multiple Output Formats**: Human-readable text or JSON for automation
- **SBC-Aware**: Detects common vendor default configurations
- **Safe & Read-Only**: Only reads system state, never modifies anything
- **Fast**: Complete analysis in < 1 second

### Complete Analyzer Suite (9 Modules)

✅ **System Information**
- OS and kernel version
- Board model detection (Raspberry Pi, Orange Pi, Radxa, etc.)
- CPU and memory information
- Architecture detection

✅ **Accounts & Authentication**
- Default vendor usernames (pi, orangepi, rock, odroid, etc.)
- Password status (empty, locked, set)
- Root account configuration
- Users with login shells
- Multiple UID 0 detection

✅ **SSH Configuration**
- PermitRootLogin settings
- Password vs. public key authentication
- Empty password permission
- X11 forwarding
- Weak ciphers and MACs
- Non-standard ports

✅ **Network & Listening Services**
- Open ports enumeration (ss/netstat)
- Services by port number (SSH, HTTP, databases, etc.)
- Dangerous legacy services (telnet, FTP, rsh)
- Database exposure (MySQL, PostgreSQL, Redis, MongoDB)
- Web admin panels on all interfaces
- Localhost vs wildcard binding

✅ **Firewall Configuration**
- UFW (Uncomplicated Firewall) status
- firewalld status
- nftables rule detection
- iptables policies and rule count
- Overall firewall presence assessment

✅ **Systemd Services**
- Enabled and running services enumeration
- Dangerous legacy services (telnet, rsh, FTP)
- Unnecessary services on headless SBCs (cups, bluetooth, avahi)
- Database and web server detection
- Container runtime detection (Docker)

✅ **Sudoers Configuration**
- NOPASSWD with ALL commands (critical!)
- Vendor default users with dangerous sudo
- Admin group configuration (%sudo, %wheel)
- Individual user privilege analysis

✅ **Filesystem & Permissions**
- SSH host key permissions
- User .ssh directory permissions
- authorized_keys file permissions
- Private key permission issues
- World-writable files in sensitive directories
- /tmp sticky bit verification

✅ **Package Management**
- Available updates detection
- Security updates identification
- Repository configuration analysis (HTTP vs HTTPS)
- Disabled GPG verification detection
- Third-party repository identification
- Unattended-upgrades configuration

## Installation

### Quick Start (Download Pre-built Static Binary)

**Coming soon**: Pre-built static binaries will be available in GitHub Releases.

For now, build from source (see below).

### Build Static Binaries (Recommended)

Static binaries have **zero dependencies** - just download and run!

```bash
# Clone the repository
git clone https://github.com/yourusername/sbc-snapshot.git
cd sbc-snapshot

# Build static binary for your target platform using cargo aliases
cargo build-arm64    # Orange Pi 5, Raspberry Pi 4/5, modern ARM SBCs
cargo build-arm32    # Raspberry Pi 2/3, older ARM SBCs
cargo build-x86      # Regular Linux servers/VMs

# Binaries will be in:
# target/aarch64-unknown-linux-musl/release/sbc-snapshot      (ARM64)
# target/armv7-unknown-linux-musleabihf/release/sbc-snapshot  (ARMv7)
# target/x86_64-unknown-linux-musl/release/sbc-snapshot       (x86_64)
```

**Cargo aliases defined in `.cargo/config.toml`:**
- `cargo build-arm64` → Build static ARM64 binary
- `cargo build-arm32` → Build static ARMv7 binary
- `cargo build-x86` → Build static x86_64 binary
- `cargo br` → Quick release build

**Why static binaries?**
- ✅ **Zero dependencies** - works on any Linux distro
- ✅ **No library version conflicts**
- ✅ **Smaller than you'd think** (~1.7MB)
- ✅ **Perfect for minimal/embedded systems**
- ✅ **Just wget/scp and run!**

### Build from Source (Regular Build)

```bash
# Build with system libraries (requires matching libc)
cargo build --release

# Binary will be at: target/release/sbc-snapshot
```

## Usage

**Important**: Run with `sudo` for complete analysis. Some checks require root access to read `/etc/shadow`, firewall rules, etc.

### Basic Usage

```bash
# Text output to terminal
sudo ./sbc-snapshot

# JSON output
sudo ./sbc-snapshot --format json

# Pretty JSON
sudo ./sbc-snapshot --format json-pretty

# Save to file
sudo ./sbc-snapshot --output snapshot.txt
sudo ./sbc-snapshot --format json --output snapshot.json
```

### Options

```
Options:
  -f, --format <FORMAT>    Output format [default: text] [possible values: text, json, json-pretty]
  -o, --output <OUTPUT>    Output file (stdout if not specified)
      --raw                Include raw data in output
      --redact             Redact sensitive information (IPs, hostnames, usernames)
  -h, --help               Print help
  -V, --version            Print version
```

## Example Output

```
═══════════════════════════════════════════════════════════════
        Security & Exposure Snapshot for SBC
═══════════════════════════════════════════════════════════════

Snapshot Version: 0.1.0
Timestamp: 2025-11-15 10:30:00 UTC
Hostname: raspberrypi
Run as root: Yes

─────────────────────────────────────────────────────────────
SYSTEM INFORMATION
─────────────────────────────────────────────────────────────
OS: Debian GNU/Linux 12 (bookworm)
Kernel: 6.1.0-18-arm64
Architecture: aarch64
Board: Raspberry Pi 4 Model B Rev 1.2
Memory: 3964 MB

─────────────────────────────────────────────────────────────
SECURITY ASSESSMENT
─────────────────────────────────────────────────────────────
Overall Risk Level: High
Total Score: 17

Findings by Severity:
  HIGH:     2
  MEDIUM:   1
  INFO:     3

─────────────────────────────────────────────────────────────
ACCOUNTS & AUTHENTICATION
─────────────────────────────────────────────────────────────

[HIGH] Default vendor username 'pi' exists
    Details: User 'pi' has login shell and password status: has password
    → Consider disabling password login for 'pi', removing the account, or at minimum ensuring a strong password is set

─────────────────────────────────────────────────────────────
NETWORK & SSH
─────────────────────────────────────────────────────────────

[HIGH] Root login via SSH is permitted with password
    Details: PermitRootLogin is set to 'yes'
    → Set PermitRootLogin to 'prohibit-password' or 'no' in /etc/ssh/sshd_config

[MEDIUM] Password authentication is enabled
    Details: PasswordAuthentication is set to 'yes'
    → Consider disabling password authentication and using public key authentication only
```

## Project Structure

```
sbc-profile/
├── Cargo.toml           # Workspace configuration
├── sbc-core/            # Core library
│   ├── src/
│   │   ├── lib.rs       # Main orchestrator
│   │   ├── types/       # Data models (Finding, Snapshot, etc.)
│   │   └── modules/     # Analyzer modules
│   │       ├── accounts.rs
│   │       ├── ssh.rs
│   │       └── system_info.rs
│   └── Cargo.toml
└── sbc-cli/             # CLI binary
    ├── src/
    │   ├── main.rs      # CLI interface
    │   └── formatter.rs # Output formatters
    └── Cargo.toml
```

## Development

### Adding a New Analyzer

1. Create a new module in `sbc-core/src/modules/`
2. Implement the `Analyzer` trait
3. Add findings with appropriate severity levels
4. Register in `lib.rs` orchestrator

Example:

```rust
use crate::types::{Finding, Severity};
use anyhow::Result;

pub struct MyAnalyzer;

impl MyAnalyzer {
    pub fn analyze(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Your analysis logic here
        findings.push(
            Finding::new(
                "my-001",
                "my-category",
                Severity::High,
                "Description of issue"
            )
            .with_details("More information")
            .with_remediation("How to fix it")
        );

        Ok(findings)
    }
}
```

### Testing

```bash
# Run tests
cargo test

# Build and test locally
cargo build
sudo ./target/debug/sbc-snapshot

# Build optimized binary
cargo build --release
```

## SBC Compatibility

Tested on:
- Raspberry Pi (Pi OS, Ubuntu)
- Works on most Linux-based SBC images

Should work on:
- Orange Pi
- Radxa Rock series
- Odroid
- Most Debian/Ubuntu-based ARM Linux distributions

## Security Considerations

- **Read-only tool**: Never modifies system state
- **Root access**: Required for complete analysis (reads `/etc/shadow`, etc.)
- **No network**: Doesn't make any network connections
- **Redaction**: Use `--redact` flag to hide sensitive data in reports

## Roadmap

- [ ] Network port scanning and service detection
- [ ] Systemd service analysis
- [ ] Sudo configuration review
- [ ] Package manager and update checks
- [ ] Firewall configuration analysis
- [ ] Baseline comparison mode
- [ ] Vendor-specific fingerprinting database
- [ ] HTML report output
- [ ] Configuration file for custom policies

## Contributing

Contributions welcome! Please:
1. Add tests for new analyzers
2. Follow existing code style
3. Update documentation
4. Test on actual SBC hardware when possible

## License

Dual licensed under your choice of:

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- BSD 3-Clause License ([LICENSE-BSD](LICENSE-BSD))

## Acknowledgments

Built for the SBC community - because `root/1234` should never be a default.
