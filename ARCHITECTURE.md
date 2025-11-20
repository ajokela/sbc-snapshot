# Architecture Overview

## Design Principles

1. **Modular**: Each analyzer is independent and can be developed/tested separately
2. **Safe**: Read-only operations, no system modifications
3. **Portable**: Single static binary, easy cross-compilation
4. **Extensible**: Simple trait-based system for adding new analyzers
5. **Informative**: Rich, structured output with actionable remediation

## Project Structure

```
sbc-profile/
├── Cargo.toml              # Workspace definition
├── README.md               # Main documentation
├── QUICKSTART.md           # Getting started guide
├── EXTENDING.md            # Guide for adding analyzers
├── ARCHITECTURE.md         # This file
│
├── sbc-core/               # Core library (reusable)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs          # Main orchestrator (SnapshotRunner)
│       ├── types/          # Data models
│       │   ├── mod.rs
│       │   ├── finding.rs      # Finding struct
│       │   ├── severity.rs     # Severity enum
│       │   └── report.rs       # Report types, Snapshot
│       └── modules/        # Analyzer modules
│           ├── mod.rs          # Analyzer trait
│           ├── accounts.rs     # Account/auth analyzer
│           ├── ssh.rs          # SSH config analyzer
│           └── system_info.rs  # System info collector
│
└── sbc-cli/                # CLI binary
    ├── Cargo.toml
    └── src/
        ├── main.rs         # CLI interface with clap
        └── formatter.rs    # Output formatters (text, JSON)
```

## Core Components

### 1. Types (`sbc-core/src/types/`)

**Finding**: Represents a single security or configuration issue

```rust
pub struct Finding {
    pub id: String,           // Unique identifier (e.g., "ssh-100")
    pub category: String,     // Module category (e.g., "ssh", "accounts")
    pub severity: Severity,   // Info/Low/Medium/High/Critical
    pub description: String,  // Short description
    pub details: Option<String>,      // Optional detailed info
    pub remediation: Option<String>,  // How to fix it
}
```

**Severity**: Enum for risk levels with scoring

```rust
pub enum Severity {
    Info,      // Score: 0
    Low,       // Score: 1
    Medium,    // Score: 3
    High,      // Score: 7
    Critical,  // Score: 10
}
```

**Snapshot**: Complete system assessment

```rust
pub struct Snapshot {
    pub metadata: SnapshotMetadata,
    pub system: SystemInfo,
    pub accounts: AccountsReport,
    pub network: NetworkReport,
    pub services: ServicesReport,
    pub filesystem: FilesystemReport,
    pub packages: PackagesReport,
    pub security_score: SecurityScore,
}
```

Each `*Report` contains:
- `findings: Vec<Finding>`
- `raw: Option<serde_json::Value>` (optional raw data)

### 2. Analyzer Trait (`sbc-core/src/modules/mod.rs`)

All analyzers implement this trait:

```rust
pub trait Analyzer {
    fn analyze(&self) -> Result<Vec<Finding>>;
    fn category(&self) -> &'static str;
}
```

### 3. Analyzer Modules (`sbc-core/src/modules/`)

#### AccountsAnalyzer (`accounts.rs`)
- Parses `/etc/passwd` for users with login shells
- Checks `/etc/shadow` for password status (requires root)
- Detects common default usernames (pi, orangepi, rock, etc.)
- Identifies multiple UID 0 users
- Checks root account password status

**Key checks:**
- Default vendor usernames
- Empty passwords
- Multiple root-equivalent users

#### SshAnalyzer (`ssh.rs`)
- Parses `/etc/ssh/sshd_config`
- Handles default values for options not explicitly set

**Key checks:**
- PermitRootLogin (yes/no/prohibit-password)
- PasswordAuthentication
- PermitEmptyPasswords
- PubkeyAuthentication
- X11Forwarding
- Weak ciphers
- Non-standard ports

#### SystemInfoCollector (`system_info.rs`)
- Reads `/etc/os-release` for distro info
- Reads `/proc/version` for kernel
- Reads `/proc/cpuinfo` for CPU and arch detection
- Reads `/proc/device-tree/model` for board detection (ARM)
- Reads `/proc/meminfo` for memory

Not an analyzer (doesn't produce findings), just collects system metadata.

### 4. Orchestrator (`sbc-core/src/lib.rs`)

**SnapshotRunner**: Coordinates all analyzers

```rust
impl SnapshotRunner {
    pub fn run(&self) -> Result<Snapshot> {
        // 1. Collect metadata (timestamp, hostname, root status)
        // 2. Collect system info
        // 3. Run all analyzers
        // 4. Calculate security score from all findings
        // 5. Build complete Snapshot
    }
}
```

### 5. CLI (`sbc-cli/src/`)

**main.rs**: Command-line interface
- Uses `clap` for argument parsing
- Checks if running as root
- Runs `SnapshotRunner`
- Formats and outputs results

**formatter.rs**: Output formatters
- `format_text()`: Human-readable report
- `format_json()`: JSON output (normal or pretty)

## Data Flow

```
User runs: sudo sbc-snapshot
         ↓
    main.rs (CLI)
         ↓
    SnapshotRunner::run()
         ↓
    ┌────────────────────────────┐
    │  Parallel analyzer calls   │
    ├────────────────────────────┤
    │  • SystemInfoCollector     │
    │  • AccountsAnalyzer        │
    │  • SshAnalyzer            │
    │  (future: more modules)    │
    └────────────────────────────┘
         ↓
    Collect all findings
         ↓
    Calculate SecurityScore
         ↓
    Build Snapshot
         ↓
    format_text() or format_json()
         ↓
    Output to stdout or file
```

## Security Score Calculation

The `SecurityScore` aggregates findings:

```rust
impl SecurityScore {
    pub fn calculate(all_findings: &[&Finding]) -> Self {
        // Sum severity scores
        // Count findings by severity
        // Determine risk level:
        //   - Critical if any CRITICAL findings
        //   - High if 4+ HIGH findings
        //   - Medium-High if any HIGH or 6+ MEDIUM
        //   - Medium if any MEDIUM
        //   - Low if any LOW
        //   - Minimal otherwise
    }
}
```

## Extension Points

### Adding a New Analyzer

1. Create new file in `sbc-core/src/modules/`
2. Implement the `Analyzer` trait
3. Add to `modules/mod.rs`
4. Call in `lib.rs` orchestrator
5. Add results to appropriate report section

See [EXTENDING.md](EXTENDING.md) for detailed guide.

### Adding a New Report Section

1. Define new `*Report` struct in `types/report.rs`
2. Add field to `Snapshot`
3. Update `Snapshot::all_findings()` to include new section
4. Update formatters to display new section

## Dependencies

### Core Library (`sbc-core`)
- `serde` + `serde_json`: Serialization
- `chrono`: Timestamps
- `anyhow` + `thiserror`: Error handling
- `nix`: Unix system calls (hostname, UID checks)
- `regex` + `lazy_static`: Pattern matching (future use)

### CLI (`sbc-cli`)
- `clap`: Command-line argument parsing
- Links to `sbc-core`

## Build Artifacts

**Debug build**: ~10MB (includes debug symbols)
**Release build**: ~1.2MB (optimized, stripped)

The release binary is fully static on Linux (when built with musl), making it trivial to deploy to SBCs.

## Future Enhancements

### Planned Analyzers
- **NetworkAnalyzer**: Open ports, listening services
- **FirewallAnalyzer**: iptables/nftables/ufw status
- **ServicesAnalyzer**: systemd units, timers
- **SudoersAnalyzer**: `/etc/sudoers` review
- **PackagesAnalyzer**: Update status, repo configuration
- **FilesystemAnalyzer**: World-writable files, SSH keys

### Planned Features
- Baseline comparison mode
- Vendor fingerprint database
- HTML report output
- Configuration file for policy rules
- CI/CD integration helpers
- Auto-remediation scripts generation

## Testing Strategy

Current: Manual testing on real systems

Future:
- Unit tests with mock file systems
- Integration tests with Docker containers
- Test fixtures for various SBC distro configs
- Continuous testing on actual SBC hardware (Raspberry Pi, etc.)

## Performance

The tool is designed to run quickly even on low-power SBCs:
- No heavy computation
- Minimal file I/O (mostly small config files)
- No network requests
- Typical runtime: <1 second on modern SBCs

## Comparison with Alternatives

| Tool | Language | Focus | Output |
|------|----------|-------|--------|
| **sbc-snapshot** | Rust | SBC defaults | Text/JSON |
| Lynis | Shell | General Linux | Text |
| OpenSCAP | C/Python | Compliance | XML |
| Bastille | Perl | Hardening | Interactive |

Our advantages:
- SBC-specific knowledge
- Single static binary
- Modern, extensible codebase
- Structured JSON output for automation
