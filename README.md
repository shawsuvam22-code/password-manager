Overview
Vaultic is a command-line password manager built entirely in Java with no external libraries. It features a unique self-healing backup system that automatically restores your vault if the primary copy is lost—protecting you from accidental deletions and file corruption.

Why Vaultic Stands Out:

🛡️ Self-Healing - Automatic recovery from backup if primary is lost

🔒 Military-Grade - AES-256-GCM with 600,000 PBKDF2 iterations

💻 Zero Dependencies - Pure Java, single file, no third-party libraries

🔑 TOTP Built-In - Complete 2FA implementation (RFC 6238)

📋 Smart Clipboard - Auto-clearing with configurable timeout

🏗️ Atomic Operations - No vault corruption, even during power loss

🎯 Key Advantages

1. 🔄 Self-Healing Backup System
The most unique feature of Vaultic is its automatic recovery mechanism:

Primary Vault Lost? → Automatic Recovery from Backup → Seamless Restoration
How it works:

Every save writes to two locations simultaneously (primary + backup)

If primary is missing, Vaultic automatically restores from backup

Restored primary is verified and re-saved

User receives clear console warnings

No manual recovery steps required

Example Recovery Flow:

$ java passwordApp get github.com
warning: primary vault unavailable (no vault found at ~/.vaultic/vault.dat) 
         - recovered from backup at ~/.vaultic-backup/vault.dat
primary vault restored from backup.
password copied to clipboard

2. 🔐 Military-Grade Security
Encryption Pipeline:

text
Master Password
       ↓
PBKDF2-HMAC-SHA256 (600,000 iterations - OWASP recommended)
       ↓
   AES-256 Key
       ↓
AES-256-GCM (Authenticated Encryption with Associated Data)
       ↓
   Encrypted Vault
Security Highlights:

600,000 PBKDF2 iterations - Exceeds OWASP recommendation (600,000)

Unique IV per save - No IV reuse, prevents pattern analysis

128-bit authentication tag - Tamper-proof verification

SecureRandom - Cryptographically secure random generation

Memory zeroing - All passwords cleared from RAM after use

No master password storage - Never persisted, never transmitted

3. 📦 Zero Dependencies
Unlike other password managers:

Tool	Dependencies	Size
Vaultic	None	38 KB
Bitwarden CLI	npm, node_modules	~200 MB
1Password CLI	Multiple system libs	~50 MB
Pass (Linux)	GPG, Xclip, etc.	Various
Advantages:

No security vulnerabilities from third-party libraries

Easy to audit (single file, ~1000 lines)

Portable - runs anywhere Java runs

Fast compilation and startup

4. 💾 Atomic Operations = No Corruption
Atomic Write Process:

1. Write encrypted data to temporary file (.tmp)
2. Attempt atomic move (system-level atomic operation)
3. If atomic move supported → instant, zero-corruption write
4. If not → fallback to regular move
Protection against:

Power failure during write

Disk full conditions

Concurrent access

System crashes

5. 🔑 TOTP 2FA Integration
Unique among offline password managers:

# Store TOTP secret
java passwordApp totp add github.com JBSWY3DPEHPK3PXP

# Generate current code
java passwordApp totp code github.com
# Output: 485927  (refreshes in 23s)
Features:

RFC 6238 compliant

30-second time steps

6-digit codes

No internet required

Works offline completely

6. 🎲 Advanced Password Generator
Guarantees:

At least one character from each selected character set

Cryptographically secure (SecureRandom)

Fisher-Yates shuffle for true randomness

Ambiguous character removal (0, O, 1, l, I)

Entropy assessment with strength bands

$ java passwordApp generate --length 24 --no-ambiguous
Generated: XkP9$mRq#2wVn@8jHx&3pLz
Strength: strong (~89 bits of entropy)
7. 🧠 Smart Clipboard Management
Clipboard Security Flow:

Password Retrieved → Copied to Clipboard → Auto-Cleared (10s)
Behavior:

Only copies when GUI available (falls back to display)

Configurable clear timeout (default: 10 seconds)

Clears by setting empty content

Notifies user throughout process

8. 🏗️ Architecture Benefits
Single Responsibility Design:

text
┌─────────────────────────────────────────────────┐
│              PasswordApp.java                   │
├─────────────────────────────────────────────────┤
│  Base32    │  CryptoUtil  │  Totp              │
│  (TOTP)    │  (AES-256)   │  (RFC 6238)        │
├────────────┼──────────────┼────────────────────┤
│  Vault     │  Password    │  Password          │
│  (Storage) │  Generator   │  Strength          │
├────────────┼──────────────┼────────────────────┤
│  Clipboard │  Cli (CLI)   │  VaultEntry        │
│  (System)  │  (Commands)  │  (Data)            │
└─────────────────────────────────────────────────┘
Benefits:

Easy to understand and modify

Each component independently testable

Clear separation of concerns

Type-safe with records

9. 🚀 Performance Optimizations
Efficient Operations:

Lazy decryption - Only decrypts when needed

Memory-mapped reads - Efficient file handling

Bounds checking - Prevents memory issues (10MB limit)

Fast serialization - Custom binary format, not JSON/XML
