# Overview

Vaultic is a command-line password manager built entirely in Java with no external libraries. It features a unique self-healing backup system that automatically restores your vault if the primary copy is lost—protecting you from accidental deletions and file corruption.

# Why Vaultic Stands Out:

🛡️ Self-Healing - Automatic recovery from backup if primary is lost

🔒 Military-Grade - AES-256-GCM with 600,000 PBKDF2 iterations

💻 Zero Dependencies - Pure Java, single file, no third-party libraries

🔑 TOTP Built-In - Complete 2FA implementation (RFC 6238)

📋 Smart Clipboard - Auto-clearing with configurable timeout

🏗️ Atomic Operations - No vault corruption, even during power loss


# Working 

## 1. Cryptography & Security Architecture
Vaultic uses modern cryptographic primitives to ensure your data is secure both on disk and in memory:

Key Derivation: When you enter your master password, Vaultic derives a 256-bit encryption key using PBKDF2WithHmacSHA256. It uses a robust 600,000 iterations combined with a 16-byte randomly generated salt, making brute-force and dictionary attacks computationally unfeasible.

Encryption: The vault payload is encrypted using AES-256 in GCM (Galois/Counter Mode). GCM is an authenticated encryption mode; it not only encrypts the data but attaches a 128-bit authentication tag to ensure the file has not been tampered with.

Memory Management: Java typically leaves strings in memory until garbage collection occurs. Vaultic strictly uses char[] and byte[] arrays for sensitive data, actively overwriting them with zeros (Arrays.fill(data, (byte) 0)) immediately after the operation completes.

## 2. Vault Storage Format
Vaultic does not store data in plaintext JSON or XML. It uses a highly efficient, custom binary serialization format. The .dat file is structured as follows:

Magic Header (ZDV1): 4 bytes identifying the file as a valid Vaultic file.

Version Byte: Ensures backward/forward compatibility.

Salt (16 bytes): Used to derive the key from your password.

IV (12 bytes): A fresh Initialization Vector generated for every single save.

Ciphertext: The AES-GCM encrypted payload containing your actual entries (sites, usernames, passwords, notes, and TOTP secrets).

## 3. Save Mechanism & Backups
Vaultic employs a dual-save, atomic write system to prevent data loss:

Atomic Writes: When saving changes, data is first written to a .tmp file. Once the write is completely successful, it is atomically swapped with the main vault.dat file. If your computer loses power mid-save, your original vault remains intact.

Auto-Healing Backup: By default, every successful save is mirrored to a secondary backup directory (~/.vaultic-backup/). If you accidentally delete or corrupt your primary vault, running any Vaultic command will seamlessly recover the data from the backup.

## 4. TOTP Engine
The 2FA system does not rely on third-party libraries. It decodes standard Base32 secrets (commonly provided as QR codes or text strings by websites) into raw bytes. It then generates a standard RFC 6238 compliant 6-digit code by applying an HMAC-SHA1 hash over the current Unix timestamp divided by 30-second intervals.

# 🎯 Key Advantages

## 1. 🔄 Self-Healing Backup System
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

## 2. 🔐 Military-Grade Security
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

## 3. 📦 Zero Dependencies
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

## 4. 💾 Atomic Operations = No Corruption
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

## 5. 🔑 TOTP 2FA Integration
Unique among offline password managers:

 Store TOTP secret
java passwordApp totp add github.com JBSWY3DPEHPK3PXP

 Generate current code
java passwordApp totp code github.com

 Output: 485927  (refreshes in 23s)
Features:

RFC 6238 compliant

30-second time steps

6-digit codes

No internet required

Works offline completely

## 6. 🎲 Advanced Password Generator
Guarantees:

At least one character from each selected character set

Cryptographically secure (SecureRandom)

Fisher-Yates shuffle for true randomness

Ambiguous character removal (0, O, 1, l, I)

Entropy assessment with strength bands

$ java passwordApp generate --length 24 --no-ambiguous
Generated: XkP9$mRq#2wVn@8jHx&3pLz
Strength: strong (~89 bits of entropy)

## 7. 🧠 Smart Clipboard Management
Clipboard Security Flow:

Password Retrieved → Copied to Clipboard → Auto-Cleared (10s)
Behavior:

Only copies when GUI available (falls back to display)

Configurable clear timeout (default: 10 seconds)

Clears by setting empty content

Notifies user throughout process

## 8. 🏗️ Architecture Benefits
Single Responsibility Design:

## passwordApp.java

| **Base32**<br>TOTP | **CryptoUtil**<br>AES-256 | **Totp**<br>RFC 6238 | 
|:------------|:-----------------|:----------------------|
|**Vault**<br>Storage |**Password Generator** | **Password Strength** | 
| **Clipboard**<br>System | **Cli**<br>Commands | **VaultEntry**<br>Data | |

Benefits:

Easy to understand and modify

Each component independently testable

Clear separation of concerns

Type-safe with records

## 9. 🚀 Performance Optimizations
Efficient Operations:

Lazy decryption - Only decrypts when needed

Memory-mapped reads - Efficient file handling

Bounds checking - Prevents memory issues (10MB limit)

Fast serialization - Custom binary format, not JSON/XML

📖 Complete Command Reference
Global Flags
|Flag	|Description	|Default|
|:------------|:-----------------|:----------------------|
|--vault PATH|	Primary vault location|	~/.vaultic/vault.dat|
|--backup-vault PATH|	Backup location|	~/.vaultic-backup/vault.dat|
|--no-backup|	Disable backup|	Off|

# Commands

**Show help / Show all the commands**
* `java passwordApp help`

**Initialize vault**
* `java passwordApp init`

**Add an entry with generated password**
* `java passwordApp add <entry name> --user <user id> --generate`

**Add an entry with your own password**
* `java passwordApp add <entry name> --user <user id>`

**List all entries**
* `java passwordApp list`

**List entries with filter**
* `java passwordApp list --filter <keyword>`

**Get a password (copies to clipboard)**
* `java passwordApp get <entry name>`

**Get a password and show on screen**
* `java passwordApp get <entry name> --show`

**Get password with custom clipboard clear time**
* `java passwordApp get <entry name> --clear-after <time>`

**Remove an entry**
* `java passwordApp remove <entry name> --yes`

**Generate a random password**
* `java passwordApp generate --length <size>`

**Generate password without ambiguous characters**
* `java passwordApp generate --length <size> --no-ambiguous`

**Change master password**
* `java passwordApp passwd`

**Add TOTP secret to an entry**
* `java passwordApp totp add <entry name> JBSWY3DPEHPK3PXP`

**Generate TOTP code**
* `java passwordApp totp code <entry name>`

**Use custom vault location**
* `java passwordApp --vault <custom location>`
* `java passwordApp --vault <custom location>`

**Change master password**
* `java passwordApp passwd`


# ⚠️ Critical Limitations

## 1. Vault File Manipulation

Anyone can edit/delete the vault file
- No file integrity protection
- No digital signatures
- File can be corrupted intentionally or accidentally
- No way to detect tampering
- Backup also can be deleted simultaneously
## 2. Forgotten Master Password

**No recovery option**
- No password hint
- No security questions
- No recovery email
- No backup codes
- Master password = ONLY key
- If forgotten, ALL data is permanently LOST
## 3. No Folder/File Locking

 Vault files are NOT protected at OS level
- Anyone with access can read/delete .vaultic folder
- No file encryption at rest (only content is encrypted)
- No folder permissions
- No anti-tamper protection
