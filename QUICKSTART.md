# Quick Start Guide

## Testing on Your SBC

### 1. Build Static Binary (Recommended)

**Static binaries have ZERO dependencies** - they'll run on any Linux SBC!

```bash
# Ensure you have the musl targets installed
rustup target add aarch64-unknown-linux-musl      # ARM64
rustup target add armv7-unknown-linux-musleabihf  # ARMv7

# Build using cargo aliases (defined in .cargo/config.toml)
cargo build-arm64    # For Orange Pi 5, Raspberry Pi 4/5, etc.
cargo build-arm32    # For Raspberry Pi 2/3, older SBCs

# Binaries will be at:
# target/aarch64-unknown-linux-musl/release/sbc-snapshot      (ARM64)
# target/armv7-unknown-linux-musleabihf/release/sbc-snapshot  (ARMv7)
```

**Why musl?**
- ✅ Truly static - no shared library dependencies
- ✅ Works on ANY Linux distro (Debian, Ubuntu, Alpine, Armbian, etc.)
- ✅ No "libc version not found" errors
- ✅ Just copy and run!

#### Alternative: Dynamic Linking (if you prefer)

```bash
# Install target
rustup target add aarch64-unknown-linux-gnu

# Build
cargo build --release --target aarch64-unknown-linux-gnu

# Binary will be at:
# target/aarch64-unknown-linux-gnu/release/sbc-snapshot
# (Note: This requires matching glibc on the target SBC)
```

### 2. Transfer to Your SBC

```bash
# Copy the binary to your SBC
scp target/aarch64-unknown-linux-gnu/release/sbc-snapshot pi@raspberrypi.local:~

# Or use whatever method you prefer (USB drive, wget from a server, etc.)
```

### 3. Run on the SBC

```bash
# SSH into your SBC
ssh pi@raspberrypi.local

# Make it executable
chmod +x sbc-snapshot

# Run with sudo for full analysis
sudo ./sbc-snapshot
```

### 4. Save the Report

```bash
# Save text report
sudo ./sbc-snapshot --output snapshot-$(date +%Y%m%d).txt

# Save JSON report for later analysis
sudo ./sbc-snapshot --format json-pretty --output snapshot-$(date +%Y%m%d).json

# Copy back to your computer
scp pi@raspberrypi.local:~/snapshot-*.json ./
```

## What You'll See on a Fresh Raspberry Pi OS

Typical findings on a default Raspberry Pi OS image:

```
Overall Risk Level: High
Total Score: 17

Findings by Severity:
  HIGH:     2
  MEDIUM:   1

ACCOUNTS & AUTHENTICATION
─────────────────────────────────────────────────────────────
[HIGH] Default vendor username 'pi' exists
    Details: User 'pi' has login shell and password status: has password
    → Consider disabling password login for 'pi', removing the account, or
      at minimum ensuring a strong password is set

NETWORK & SSH
─────────────────────────────────────────────────────────────
[HIGH] Root login via SSH is permitted with password
    Details: PermitRootLogin is set to 'yes'
    → Set PermitRootLogin to 'prohibit-password' or 'no' in /etc/ssh/sshd_config

[MEDIUM] Password authentication is enabled
    Details: PasswordAuthentication is set to 'yes'
    → Consider disabling password authentication and using public key authentication only
```

## Common Findings by SBC Vendor

### Raspberry Pi OS (Bookworm and newer)
- Default `pi` user with password
- SSH password auth enabled
- Root login may be permitted

### Armbian
- Default `root` user with password `1234` (forces change on first login)
- Password authentication enabled
- Various services depending on image variant

### DietPi
- Default `dietpi` and `root` users
- Password auth enabled
- Minimal services (good!)

### Orange Pi Official Images
- Default `orangepi` user
- Often has password auth enabled
- May have additional web panels running

## Hardening Workflow

Use this tool in your SBC hardening workflow:

1. **Baseline**: Run immediately after flashing image
   ```bash
   sudo ./sbc-snapshot --output baseline.json --format json-pretty
   ```

2. **Harden**: Apply security fixes based on findings

3. **Verify**: Run again to confirm
   ```bash
   sudo ./sbc-snapshot --output hardened.json --format json-pretty
   ```

4. **Compare**: Check the difference in security scores

## Integration with Ansible/Scripts

```bash
#!/bin/bash
# Example: Run on multiple SBCs and collect reports

SBCS=(
    "pi@rpi-01.local"
    "pi@rpi-02.local"
    "orangepi@opi-01.local"
)

for sbc in "${SBCS[@]}"; do
    echo "Scanning $sbc..."
    ssh "$sbc" 'sudo ./sbc-snapshot --format json' > "reports/${sbc}.json"
done
```

## Troubleshooting

### "Failed to read /etc/shadow"
- Not running as root
- Solution: Use `sudo`

### "Failed to read SSH config file"
- SSH might not be installed (rare)
- Or config is in a non-standard location

### No findings at all
- Tool may not be detecting your distro properly
- Check that `/etc/os-release` exists
- Open an issue with your SBC model and OS

### Cross-compilation fails
- Try using `cross` instead of direct cargo cross-compilation
- Ensure you have the right target installed: `rustup target list`

## Next Steps

After running the tool:

1. **Review findings** - Understand each issue
2. **Prioritize** - Fix CRITICAL and HIGH severity first
3. **Apply fixes** - Follow remediation advice
4. **Re-run** - Verify improvements
5. **Document** - Keep snapshots for compliance/audit purposes

## Getting Help

- Check the main [README.md](README.md)
- See [EXTENDING.md](EXTENDING.md) for adding custom checks
- Open an issue on GitHub
