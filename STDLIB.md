#Standard library dependencies

*** MARKDOWN ***

**CliError (Exception)**
Custom exception used to cleanly exit the CLI with a specific OS error code and user-facing message.

* `CliError(String message, int exitCode)`
  Constructs the exception, passing the message to standard error and returning the exit code to the OS.

**Base32**
Handles Base32 encoding and decoding, specifically tailored for parsing TOTP secrets.

* `decode(String input) -> byte[]`
  Strips padding, spaces, and dashes from a Base32 string and decodes it into a raw byte array.
* `encode(byte[] data) -> String`
  Encodes a raw byte array into a standard Base32 string representation.

**CryptoUtil**
Provides low-level cryptographic primitives for key derivation and AES-GCM encryption.

* `deriveKey(char[] password, byte[] salt, int iterations) -> SecretKey`
  Derives a 256-bit AES key using `PBKDF2WithHmacSHA256`. Automatically clears the `PBEKeySpec` from memory after generation.
* `encrypt(byte[] plaintext, SecretKey key, byte[] iv) -> byte[]`
  Encrypts data using `AES/GCM/NoPadding` with a 128-bit authentication tag.
* `decrypt(byte[] ciphertext, SecretKey key, byte[] iv) -> byte[]`
  Decrypts data and verifies the GCM authentication tag. Throws `AEADBadTagException` on failure.
* `randomBytes(int len) -> byte[]`
  Returns an array of cryptographically secure random bytes of the specified length.

**Vault**
The core database manager handling atomic I/O, serialization, and state management of password entries.

* `Vault.create(Path primary, Path backup, char[] master, boolean force) -> Vault`
  Initializes a new encrypted vault at the target paths, generating a new salt and deriving the initial key.
* `Vault.open(Path primary, Path backup, char[] master) -> Vault`
  Attempts to decrypt and load the vault into memory. Automatically falls back to the backup path if the primary is missing or corrupted, and attempts self-healing.
* `save()`
  Serializes the vault state, generates a fresh IV, encrypts the payload, and performs an atomic write to both primary and backup locations.
* `addEntry(VaultEntry entry)` / `getEntry(String site)` / `removeEntry(String site)`
  Standard CRUD operations for managing `VaultEntry` records in memory.
* `listEntries(String filter) -> List<VaultEntry>`
  Returns a list of all entries in the vault. If `filter` is provided, returns only entries where the site name contains the filter string (case-insensitive).
* `setTotpSecret(String site, String secret)`
  Updates an existing vault entry to include a Base32 encoded TOTP secret. Throws `CliError` if the site does not exist.
* `rekey(char[] newMasterPassword)`
  Generates a new salt, derives a new encryption key from the provided password, and triggers a full save to rewrite the ciphertext.

**VaultEntry (Record)**
The immutable data structure representing a single saved credential.
* `site() -> String`
  The identifier or URL for the entry.
* `username() -> String`
  The login username (nullable).
* `password() -> char[]`
  The raw password.
* `notes() -> String`
  Additional encrypted notes (nullable).
* `createdAt() -> long`
  Unix epoch timestamp of creation.
* `totpSecret() -> String`
  Base32 encoded 2FA secret (nullable).

**Totp**
Generates Time-Based One-Time Passwords adhering to standard 2FA protocols (RFC 6238).

* `generateCode(byte[] secretBytes, long epochSeconds) -> String`
  Calculates the 6-digit TOTP code for the given timestamp using `HmacSHA1`.
* `secondsRemaining(long epochSeconds) -> int`
  Calculates the number of seconds until the current 30-second TOTP window expires.

**PasswordGenerator**
A secure random password generator supporting multiple character pools.

* `generate(int length, boolean lower, boolean upper, boolean digits, boolean symbols, boolean noAmbiguous) -> char[]`
  Generates a randomized character array guaranteeing at least one character from each selected pool. Uses Fisher-Yates shuffle to randomize character placement.
* `estimateBits(int length, boolean lower, boolean upper, boolean digits, boolean symbols) -> double`
  Calculates the theoretical entropy of a generated password based on the active character pools.

**PasswordStrength**
Heuristic-based password strength evaluator.

* `assess(char[] password) -> String`
  Checks the password against a hardcoded blacklist of common passwords. If not blacklisted, estimates the entropy based on length and character sets used, returning a string rating (weak, fair, strong, excellent) alongside the entropy bits.

**ClipboardUtil**
* `copy(String text) -> boolean`
  Attempts to push a string to the system clipboard via `java.awt.Toolkit`. Returns `false` if the clipboard is unavailable (e.g., in a headless environment).

**ClipboardUtil.Cli**
The command-line interface handler that parses arguments, manages user input/output, and routes commands to the underlying `Vault` operations.

* `run(String[] args)`
  The main entry point for the CLI application. Parses the first argument as a command and routes it to the appropriate sub-handler (`init`, `add`, `get`, `list`, `remove`, `totp`, `generate`, `passwd`, `help`).
* `vaultPath(String[] args) -> Path` *(internal)*
  Resolves the primary vault file path, defaulting to `~/.vaultic/vault.dat` unless overridden by the `--vault` flag.
* `backupVaultPath(String[] args) -> Path` *(internal)*
  Resolves the backup vault file path, defaulting to `~/.vaultic-backup/vault.dat` unless overridden by `--backup-vault` or disabled entirely via `--no-backup`.
* `getFlag(String[] args, String name, String defaultValue) -> String` *(internal)*
  Extracts the value of a key-value argument flag from the command line array.
* `hasFlag(String[] args, String name) -> boolean` *(internal)*
  Checks for the presence of a standalone boolean flag in the command line array.
* `readPassword(String prompt) -> char[]` *(internal)*
  Securely reads a password from standard input without echoing it to the console using `System.console().readPassword()`. Falls back to standard `System.in` reads if a console is not attached.
* `printUsage()` *(internal)*
  Outputs the standard help menu and command list to the terminal.
