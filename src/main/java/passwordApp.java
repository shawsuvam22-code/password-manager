import org.w3c.dom.ls.LSOutput;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.sql.SQLOutput;
import java.time.Instant;
import java.util.*;

public final class passwordApp {

    public static void main(String[] args) {
    }
    static final class CliError extends Exception {
        final int exitCode;

        CliError(String message, int exitCode) {
            super(message);
            this.exitCode = exitCode;
        }
    }


    static final class Base32 {
        private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        static byte[] decode(String input) {
            String clean = input.trim().toUpperCase(Locale.ROOT).replace("=", "");
            long buffer = 0;
            int bitsLeft = 0;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (char c : clean.toCharArray()) {
                int val = ALPHABET.indexOf(c);
                if (val < 0) {
                    continue; // skip spaces/dashes some services include in secrets
                }
                buffer = (buffer << 5) | val;
                bitsLeft += 5;
                if (bitsLeft >= 8) {
                    bitsLeft -= 8;
                    out.write((int) ((buffer >> bitsLeft) & 0xFF));
                }
            }
            return out.toByteArray();
        }

        static String encode(byte[] data) {
            StringBuilder sb = new StringBuilder();
            long buffer = 0;
            int bitsLeft = 0;
            for (byte b : data) {
                buffer = (buffer << 8) | (b & 0xFF);
                bitsLeft += 8;
                while (bitsLeft >= 5) {
                    bitsLeft -= 5;
                    sb.append(ALPHABET.charAt((int) ((buffer >> bitsLeft) & 0x1F)));
                }
            }
            if (bitsLeft > 0) {
                sb.append(ALPHABET.charAt((int) ((buffer << (5 - bitsLeft)) & 0x1F)));
            }
            return sb.toString();
        }
    }
    static final class CryptoUtil {
        static final int SALT_LEN = 16;
        static final int IV_LEN = 12;
        static final int GCM_TAG_BITS = 128;
        static final int KEY_BITS = 256;

        static SecretKey deriveKey(char[] password, byte[] salt, int iterations) throws GeneralSecurityException {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                byte[] keyBytes = factory.generateSecret(spec).getEncoded();
                SecretKey key = new SecretKeySpec(keyBytes, "AES");
                Arrays.fill(keyBytes, (byte) 0);
                return key;
            } finally {
                spec.clearPassword();
            }
        }

        static byte[] encrypt(byte[] plaintext, SecretKey key, byte[] iv) throws GeneralSecurityException {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            return cipher.doFinal(plaintext);
        }

        static byte[] decrypt(byte[] ciphertext, SecretKey key, byte[] iv) throws GeneralSecurityException {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            return cipher.doFinal(ciphertext);
        }

        static byte[] randomBytes(int len) {
            byte[] b = new byte[len];
            new SecureRandom().nextBytes(b);
            return b;
        }
    }
    record VaultEntry(String site, String username, char[] password, String notes,
                      long createdAt, String totpSecret) {
    }

    static final class Vault {
        private static final byte[] MAGIC = {'Z', 'D', 'V', '1'};
        private static final int VERSION = 1;
        private static final int DEFAULT_ITERATIONS = 600_000;

        final Path path;
        final Path backupPath; // nullable
        private byte[] salt;
        private int iterations;
        private SecretKey key;
        private final List<VaultEntry> entries;

        private Vault(Path path, Path backupPath, byte[] salt, int iterations, SecretKey key,
                      List<VaultEntry> entries) {
            this.path = path;
            this.backupPath = backupPath;
            this.salt = salt;
            this.iterations = iterations;
            this.key = key;
            this.entries = entries;
        }

        static Vault create(Path primaryPath, Path backupPath, char[] masterPassword, boolean force)
                throws IOException, GeneralSecurityException, CliError {
            if (Files.exists(primaryPath)) {
                throw new CliError("a vault already exists at " + primaryPath, 4);
            }
            if (!force && backupPath != null && Files.exists(backupPath)) {
                throw new CliError("a backup vault already exists at " + backupPath
                        + " - your primary may simply be missing. Run any command (e.g. 'list') to "
                        + "auto-recover it, or re-run init with --force to overwrite the backup and start fresh.", 4);
            }
            byte[] salt = CryptoUtil.randomBytes(CryptoUtil.SALT_LEN);
            int iterations = DEFAULT_ITERATIONS;
            SecretKey key = CryptoUtil.deriveKey(masterPassword, salt, iterations);
            Vault vault = new Vault(primaryPath, backupPath, salt, iterations, key, new ArrayList<>());
            vault.save();
            return vault;
        }

        static Vault open(Path primaryPath, Path backupPath, char[] masterPassword)
                throws IOException, GeneralSecurityException, CliError {
            Exception primaryError;
            if (Files.exists(primaryPath)) {
                try {
                    LoadedData d = openSingle(primaryPath, masterPassword);
                    return new Vault(primaryPath, backupPath, d.salt(), d.iterations(), d.key(), d.entries());
                } catch (CliError | IOException | GeneralSecurityException e) {
                    primaryError = e;
                }
            } else {
                primaryError = new CliError("no vault found at " + primaryPath, 3);
            }

            if (backupPath != null && Files.exists(backupPath)) {
                try {
                    LoadedData d = openSingle(backupPath, masterPassword);
                    System.err.println("warning: primary vault unavailable (" + primaryError.getMessage()
                            + ") - recovered from backup at " + backupPath);
                    Vault healed = new Vault(primaryPath, backupPath, d.salt(), d.iterations(), d.key(), d.entries());
                    try {
                        healed.save();
                        System.err.println("primary vault restored from backup.");
                    } catch (IOException healError) {
                        System.err.println("warning: could not restore the primary copy (" + healError.getMessage()
                                + ") - continuing with the recovered data from backup only.");
                    }
                    return healed;
                } catch (CliError | IOException | GeneralSecurityException backupError) {
                    throw new CliError("vault open failed - primary: " + primaryError.getMessage()
                            + "; backup: " + backupError.getMessage(), 3);
                }
            }

            if (primaryError instanceof CliError ce) {
                throw ce;
            } else if (primaryError instanceof IOException ioe) {
                throw ioe;
            } else if (primaryError instanceof GeneralSecurityException gse) {
                throw gse;
            } else {
                throw new IllegalStateException("unexpected exception type", primaryError);
            }
        }

        void save() throws IOException, GeneralSecurityException {
            byte[] fileBytes = buildEncryptedFile();
            writeAtomically(path, fileBytes);
            if (backupPath != null) {
                try {
                    writeAtomically(backupPath, fileBytes);
                } catch (IOException e) {
                    System.err.println("warning: primary vault saved, but the backup copy at " + backupPath
                            + " could not be written (" + e.getMessage() + "). You are not protected against "
                            + "losing the primary until this is fixed.");
                }
            }
        }

        void addEntry(VaultEntry entry) throws CliError {
            if (findIndex(entry.site()) >= 0) {
                throw new CliError("an entry for '" + entry.site() + "' already exists", 4);
            }
            entries.add(entry);
        }

        Optional<VaultEntry> getEntry(String site) {
            int i = findIndex(site);
            return i >= 0 ? Optional.of(entries.get(i)) : Optional.empty();
        }

        boolean removeEntry(String site) {
            int i = findIndex(site);
            if (i < 0) {
                return false;
            }
            entries.remove(i);
            return true;
        }

        List<VaultEntry> listEntries(String filter) {
            List<VaultEntry> out = new ArrayList<>();
            for (VaultEntry e : entries) {
                if (filter == null || e.site().toLowerCase(Locale.ROOT).contains(filter.toLowerCase(Locale.ROOT))) {
                    out.add(e);
                }
            }
            return out;
        }

        void setTotpSecret(String site, String secret) throws CliError {
            int i = findIndex(site);
            if (i < 0) {
                throw new CliError("no entry for '" + site + "' - add it first", 4);
            }
            VaultEntry old = entries.get(i);
            entries.set(i, new VaultEntry(old.site(), old.username(), old.password(), old.notes(),
                    old.createdAt(), secret));
        }

        void rekey(char[] newMasterPassword) throws GeneralSecurityException, IOException {
            byte[] newSalt = CryptoUtil.randomBytes(CryptoUtil.SALT_LEN);
            SecretKey newKey = CryptoUtil.deriveKey(newMasterPassword, newSalt, this.iterations);
            this.salt = newSalt;
            this.key = newKey;
            save();
        }

        private int findIndex(String site) {
            for (int i = 0; i < entries.size(); i++) {
                if (entries.get(i).site().equalsIgnoreCase(site)) {
                    return i;
                }
            }
            return -1;
        }
        private record LoadedData(byte[] salt, int iterations, SecretKey key, List<VaultEntry> entries) {
        }

        private static LoadedData openSingle(Path filePath, char[] masterPassword)
                throws IOException, GeneralSecurityException, CliError {
            byte[] fileBytes = Files.readAllBytes(filePath);
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(fileBytes));

            byte[] magic = new byte[4];
            in.readFully(magic);
            if (!Arrays.equals(magic, MAGIC)) {
                throw new CliError("not a valid vault file: " + filePath, 3);
            }
            int version = in.readUnsignedByte();
            if (version != VERSION) {
                throw new CliError("unsupported vault version " + version + " at " + filePath, 3);
            }
            byte[] salt = new byte[CryptoUtil.SALT_LEN];
            in.readFully(salt);
            int iterations = in.readInt();
            byte[] iv = new byte[CryptoUtil.IV_LEN];
            in.readFully(iv);
            byte[] ciphertext = in.readAllBytes();

            SecretKey key = CryptoUtil.deriveKey(masterPassword, salt, iterations);
            byte[] plaintext;
            try {
                plaintext = CryptoUtil.decrypt(ciphertext, key, iv);
            } catch (AEADBadTagException e) {
                throw new CliError("wrong master password or corrupted vault at " + filePath, 2);
            }
            List<VaultEntry> entries = deserializeEntries(plaintext);
            Arrays.fill(plaintext, (byte) 0);
            return new LoadedData(salt, iterations, key, entries);
        }

        private byte[] buildEncryptedFile() throws IOException, GeneralSecurityException {
            byte[] plaintext = serializeEntries(entries);
            byte[] iv = CryptoUtil.randomBytes(CryptoUtil.IV_LEN); // fresh IV every save, never reused
            byte[] ciphertext = CryptoUtil.encrypt(plaintext, key, iv);
            Arrays.fill(plaintext, (byte) 0);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(bos);
            dos.write(MAGIC);
            dos.writeByte(VERSION);
            dos.write(salt);
            dos.writeInt(iterations);
            dos.write(iv);
            dos.write(ciphertext);
            dos.flush();
            return bos.toByteArray();
        }

        private static void writeAtomically(Path target, byte[] data) throws IOException {
            Path parent = target.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path tmp = target.resolveSibling(target.getFileName().toString() + ".tmp");
            Files.write(tmp, data);
            try {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        }


        private static void writeField(DataOutputStream out, byte[] data) throws IOException {
            out.writeInt(data.length);
            out.write(data);
        }

        private static byte[] readField(DataInputStream in) throws IOException {
            int len = in.readInt();
            if (len < 0 || len > 10_000_000) {
                throw new IOException("corrupt vault: implausible field length");
            }
            byte[] buf = new byte[len];
            in.readFully(buf);
            return buf;
        }

        private static byte[] serializeEntries(List<VaultEntry> entries) throws IOException {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(bos);
            dos.writeInt(entries.size());
            for (VaultEntry e : entries) {
                writeField(dos, e.site().getBytes(StandardCharsets.UTF_8));
                writeField(dos, (e.username() == null ? "" : e.username()).getBytes(StandardCharsets.UTF_8));
                writeField(dos, charsToUtf8Bytes(e.password()));
                writeField(dos, (e.notes() == null ? "" : e.notes()).getBytes(StandardCharsets.UTF_8));
                dos.writeLong(e.createdAt());
                boolean hasTotp = e.totpSecret() != null && !e.totpSecret().isEmpty();
                dos.writeBoolean(hasTotp);
                if (hasTotp) {
                    writeField(dos, e.totpSecret().getBytes(StandardCharsets.UTF_8));
                }
            }
            dos.flush();
            return bos.toByteArray();
        }

        private static List<VaultEntry> deserializeEntries(byte[] data) throws IOException {
            List<VaultEntry> list = new ArrayList<>();
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
            int count = dis.readInt();
            for (int i = 0; i < count; i++) {
                String site = new String(readField(dis), StandardCharsets.UTF_8);
                String username = new String(readField(dis), StandardCharsets.UTF_8);
                char[] password = utf8BytesToChars(readField(dis));
                String notes = new String(readField(dis), StandardCharsets.UTF_8);
                long createdAt = dis.readLong();
                boolean hasTotp = dis.readBoolean();
                String totpSecret = hasTotp ? new String(readField(dis), StandardCharsets.UTF_8) : null;
                list.add(new VaultEntry(site, username.isEmpty() ? null : username, password,
                        notes.isEmpty() ? null : notes, createdAt, totpSecret));
            }
            return list;
        }


        private static byte[] charsToUtf8Bytes(char[] chars) {
            ByteBuffer bb = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
            byte[] out = new byte[bb.remaining()];
            bb.get(out);
            if (bb.hasArray()) {
                Arrays.fill(bb.array(), (byte) 0);
            }
            return out;
        }

        private static char[] utf8BytesToChars(byte[] bytes) {
            CharBuffer cb = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(bytes));
            char[] out = new char[cb.remaining()];
            cb.get(out);
            return out;
        }
    }
    static final class Totp {
        static final int STEP_SECONDS = 30;
        static final int DIGITS = 6;

        static String generateCode(byte[] secretBytes, long epochSeconds) throws GeneralSecurityException {
            long counter = epochSeconds / STEP_SECONDS;
            byte[] counterBytes = new byte[8];
            for (int i = 7; i >= 0; i--) {
                counterBytes[i] = (byte) (counter & 0xFF);
                counter >>>= 8;
            }
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secretBytes, "HmacSHA1"));
            byte[] hash = mac.doFinal(counterBytes);

            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);
            int code = binary % (int) Math.pow(10, DIGITS);
            return String.format("%0" + DIGITS + "d", code);
        }

        static int secondsRemaining(long epochSeconds) {
            return STEP_SECONDS - (int) (epochSeconds % STEP_SECONDS);
        }
    }

    static final class PasswordGenerator {
        private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
        private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private static final String DIGITS = "0123456789";
        private static final String SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/";
        private static final String AMBIGUOUS = "0O1lI";

        static char[] generate(int length, boolean lower, boolean upper, boolean digits,
                               boolean symbols, boolean noAmbiguous) {
            List<String> categories = new ArrayList<>();
            if (lower) categories.add(strip(LOWER, noAmbiguous));
            if (upper) categories.add(strip(UPPER, noAmbiguous));
            if (digits) categories.add(strip(DIGITS, noAmbiguous));
            if (symbols) categories.add(strip(SYMBOLS, noAmbiguous));
            if (categories.isEmpty()) categories.add(strip(LOWER, noAmbiguous));

            StringBuilder poolBuilder = new StringBuilder();
            for (String c : categories) poolBuilder.append(c);
            String fullPool = poolBuilder.toString();

            SecureRandom random = new SecureRandom();
            char[] result = new char[Math.max(length, categories.size())];

            int idx = 0;
            for (String cat : categories) {
                result[idx++] = cat.charAt(random.nextInt(cat.length()));
            }
            for (; idx < result.length; idx++) {
                result[idx] = fullPool.charAt(random.nextInt(fullPool.length()));
            }

            for (int i = result.length - 1; i > 0; i--) {
                int j = random.nextInt(i + 1);
                char tmp = result[i];
                result[i] = result[j];
                result[j] = tmp;
            }
            return result;
        }

        static double estimateBits(int length, boolean lower, boolean upper, boolean digits, boolean symbols) {
            int poolSize = 0;
            if (lower) poolSize += 26;
            if (upper) poolSize += 26;
            if (digits) poolSize += 10;
            if (symbols) poolSize += SYMBOLS.length();
            if (poolSize == 0) poolSize = 26;
            return length * (Math.log(poolSize) / Math.log(2));
        }

        private static String strip(String set, boolean noAmbiguous) {
            if (!noAmbiguous) return set;
            StringBuilder sb = new StringBuilder();
            for (char c : set.toCharArray()) {
                if (AMBIGUOUS.indexOf(c) < 0) sb.append(c);
            }
            return sb.toString();
        }
    }
    static final class PasswordStrength {

        private static final Set<String> COMMON = Set.of(
                "password", "123456", "12345678", "qwerty", "letmein", "admin", "welcome",
                "monkey", "dragon", "111111", "password1", "iloveyou", "abc123", "123456789",
                "sunshine", "princess", "football", "master", "login", "solo", "shadow",
                "michael", "superman", "batman", "trustno1", "hello", "freedom", "whatever",
                "starwars", "888888", "121212", "qwerty123", "1q2w3e4r", "000000"
        );

        static String assess(char[] password) {
            String joined = new String(password).toLowerCase(Locale.ROOT);
            if (COMMON.contains(joined)) {
                return "weak (this is one of the most commonly leaked passwords)";
            }

            boolean hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false;
            for (char c : password) {
                if (Character.isLowerCase(c)) hasLower = true;
                else if (Character.isUpperCase(c)) hasUpper = true;
                else if (Character.isDigit(c)) hasDigit = true;
                else hasSymbol = true;
            }
            double bits = PasswordGenerator.estimateBits(password.length, hasLower, hasUpper, hasDigit, hasSymbol);

            String band;
            if (bits < 35) band = "weak";
            else if (bits < 60) band = "fair";
            else if (bits < 90) band = "strong";
            else band = "excellent";

            return String.format("%s (~%.0f bits of entropy)", band, bits);
        }
    }

    static final class ClipboardUtil {
        static boolean copy(String text) {
            try {
                java.awt.datatransfer.Clipboard clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(new java.awt.datatransfer.StringSelection(text), null);
                return true;
            } catch (Throwable t) {
                return false;
            }
        }
        static final class Cli {

            static void run(String[] args) throws Exception {
                if (args.length == 0) {
                    printUsage();
                    throw new CliError("no command given", 4);
                }
                String command = args[0];
                String[] rest = Arrays.copyOfRange(args, 1, args.length);
                switch (command) {
                    case "init" -> cmdInit(rest);
                    case "add" -> cmdAdd(rest);
                    case "get" -> cmdGet(rest);
                    case "list" -> cmdList(rest);
                    case "remove" -> cmdRemove(rest);
                    case "totp" -> cmdTotp(rest);
                    case "generate" -> cmdGenerate(rest);
                    case "passwd" -> cmdPasswd(rest);
                    case "help", "--help", "-h" -> printUsage();
                    default -> throw new CliError("unknown command '" + command + "' (try 'help')", 4);
                }
            }

            private static void cmdInit(String[] args) throws Exception {
                Path vp = vaultPath(args);
                Path bp = backupVaultPath(args);
                char[] pw1 = readPassword("Set master password: ");
                char[] pw2 = readPassword("Confirm master password: ");
                if (!Arrays.equals(pw1, pw2)) {
                    Arrays.fill(pw1, (char) 0);
                    Arrays.fill(pw2, (char) 0);
                    throw new CliError("passwords did not match", 4);
                }
                Arrays.fill(pw2, (char) 0);
                Vault.create(vp, bp, pw1, hasFlag(args, "--force"));
                Arrays.fill(pw1, (char) 0);
                System.out.println("vault created at " + vp
                        + (bp != null ? " (backup copy at " + bp + ")"
                        : " (no backup copy - omit --no-backup, or set --backup-vault PATH, to enable one)"));
            }

            private static void cmdAdd(String[] args) throws Exception {
                if (args.length == 0) {
                    throw new CliError(
                            "usage: add <site> [--user NAME] [--notes TEXT] [--generate] [--length N]", 4);
                }
                String site = args[0];
                String user = getFlag(args, "--user", null);
                String notes = getFlag(args, "--notes", "");

                char[] master = readPassword("Master password: ");
                Vault vault = Vault.open(vaultPath(args), backupVaultPath(args), master);
                Arrays.fill(master, (char) 0);

                boolean generated = hasFlag(args, "--generate");
                char[] entryPassword;
                if (generated) {
                    int length = Integer.parseInt(getFlag(args, "--length", "20"));
                    entryPassword = PasswordGenerator.generate(length, true, true, true, true, hasFlag(args, "--no-ambiguous"));
                } else {
                    entryPassword = readPassword("Password for " + site + ": ");
                }

                vault.addEntry(new VaultEntry(site, user, entryPassword, notes, Instant.now().getEpochSecond(), null));
                vault.save();
                System.out.println("saved entry for " + site);

                if (generated) {
                    System.out.println("generated: " + new String(entryPassword));
                    System.out.println("strength: " + PasswordStrength.assess(entryPassword));
                }
                Arrays.fill(entryPassword, (char) 0);
            }

            private static void cmdGet(String[] args) throws Exception {
                if (args.length == 0) {
                    throw new CliError("usage: get <site> [--show] [--clear-after SECONDS]", 4);
                }
                String site = args[0];
                boolean show = hasFlag(args, "--show");

                char[] master = readPassword("Master password: ");
                Vault vault = Vault.open(vaultPath(args), backupVaultPath(args), master);
                Arrays.fill(master, (char) 0);

                VaultEntry entry = vault.getEntry(site).orElseThrow(() -> new CliError("no entry for '" + site + "'", 4));

                if (show) {
                    System.out.println("username: " + (entry.username() == null ? "(none)" : entry.username()));
                    System.out.println("password: " + new String(entry.password()));
                    return;
                }

                boolean copied = ClipboardUtil.copy(new String(entry.password()));
                if (!copied) {
                    System.out.println("clipboard unavailable in this environment; password: " + new String(entry.password()));
                    return;
                }
                int clearAfter = Integer.parseInt(getFlag(args, "--clear-after", "10"));
                System.out.println("password copied to clipboard, clearing in " + clearAfter + "s...");
                Thread.sleep(clearAfter * 1000L);
                ClipboardUtil.copy("");
                System.out.println("clipboard cleared");
            }

            private static void cmdList(String[] args) throws Exception {
                String filter = getFlag(args, "--filter", null);
                char[] master = readPassword("Master password: ");
                Vault vault = Vault.open(vaultPath(args), backupVaultPath(args), master);
                Arrays.fill(master, (char) 0);

                List<VaultEntry> entries = vault.listEntries(filter);
                if (entries.isEmpty()) {
                    System.out.println("(no entries)");
                    return;
                }
                for (VaultEntry e : entries) {
                    System.out.println(e.site() + (e.totpSecret() != null ? "  [2FA]" : ""));
                }
            }

            private static void cmdRemove(String[] args) throws Exception {
                if (args.length == 0) {
                    throw new CliError("usage: remove <site> [--yes]", 4);
                }
                String site = args[0];
                if (!hasFlag(args, "--yes")) {
                    System.out.print("remove '" + site + "'? type 'yes' to confirm: ");
                    System.out.flush();
                    BufferedReader r = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
                    String answer = r.readLine();
                    if (!"yes".equalsIgnoreCase(answer == null ? "" : answer.trim())) {
                        System.out.println("cancelled");
                        return;
                    }
                }
                char[] master = readPassword("Master password: ");
                Vault vault = Vault.open(vaultPath(args), backupVaultPath(args), master);
                Arrays.fill(master, (char) 0);

                if (vault.removeEntry(site)) {
                    vault.save();
                    System.out.println("removed " + site);
                } else {
                    throw new CliError("no entry for '" + site + "'", 4);
                }
            }

            private static void cmdTotp(String[] args) throws Exception {
                if (args.length == 0) {
                    throw new CliError("usage: totp <add|code> ...", 4);
                }
                String sub = args[0];
                String[] rest = Arrays.copyOfRange(args, 1, args.length);

                if (sub.equals("add")) {
                    if (rest.length < 2) {
                        throw new CliError("usage: totp add <site> <base32-secret>", 4);
                    }
                    String site = rest[0];
                    String secret = rest[1].toUpperCase(Locale.ROOT).replace(" ", "");
                    Base32.decode(secret); // validate it decodes without throwing

                    char[] master = readPassword("Master password: ");
                    Vault vault = Vault.open(vaultPath(rest), backupVaultPath(rest), master);
                    Arrays.fill(master, (char) 0);

                    vault.setTotpSecret(site, secret);
                    vault.save();
                    System.out.println("TOTP secret saved for " + site);

                } else if (sub.equals("code")) {
                    if (rest.length < 1) {
                        throw new CliError("usage: totp code <site>", 4);
                    }
                    String site = rest[0];
                    char[] master = readPassword("Master password: ");
                    Vault vault = Vault.open(vaultPath(rest), backupVaultPath(rest), master);
                    Arrays.fill(master, (char) 0);

                    VaultEntry entry = vault.getEntry(site).orElseThrow(() -> new CliError("no entry for '" + site + "'", 4));
                    if (entry.totpSecret() == null) {
                        throw new CliError("no TOTP secret registered for '" + site + "' - use 'totp add' first", 4);
                    }
                    byte[] secretBytes = Base32.decode(entry.totpSecret());
                    long now = Instant.now().getEpochSecond();
                    String code = Totp.generateCode(secretBytes, now);
                    System.out.println(code + "  (refreshes in " + Totp.secondsRemaining(now) + "s)");

                } else {
                    throw new CliError("unknown totp subcommand '" + sub + "'", 4);
                }
            }

            private static void cmdGenerate(String[] args) {
                int length = Integer.parseInt(getFlag(args, "--length", "20"));
                boolean noAmbiguous = hasFlag(args, "--no-ambiguous");
                char[] pw = PasswordGenerator.generate(length, true, true, true, true, noAmbiguous);
                System.out.println(new String(pw));
                System.out.println("strength: " + PasswordStrength.assess(pw));
                Arrays.fill(pw, (char) 0);
            }

            private static void cmdPasswd(String[] args) throws Exception {
                char[] oldMaster = readPassword("Current master password: ");
                Vault vault = Vault.open(vaultPath(args), backupVaultPath(args), oldMaster);
                Arrays.fill(oldMaster, (char) 0);

                char[] newMaster1 = readPassword("New master password: ");
                char[] newMaster2 = readPassword("Confirm new master password: ");
                if (!Arrays.equals(newMaster1, newMaster2)) {
                    Arrays.fill(newMaster1, (char) 0);
                    Arrays.fill(newMaster2, (char) 0);
                    throw new CliError("passwords did not match", 4);
                }
                Arrays.fill(newMaster2, (char) 0);
                vault.rekey(newMaster1);
                Arrays.fill(newMaster1, (char) 0);
                System.out.println("master password updated");
            }

            private static Path vaultPath(String[] args) {
                String custom = getFlag(args, "--vault", null);
                if (custom != null) {
                    return Paths.get(custom);
                }
                return Paths.get(System.getProperty("user.home"), ".vaultic", "vault.dat");
            }

            private static Path backupVaultPath(String[] args) {
                if (hasFlag(args, "--no-backup")) {
                    return null;
                }
                String custom = getFlag(args, "--backup-vault", null);
                if (custom != null) {
                    return Paths.get(custom);
                }

                return Paths.get(System.getProperty("user.home"), ".vaultic-backup", "vault.dat");
            }

            private static String getFlag(String[] args, String name, String defaultValue) {
                for (int i = 0; i < args.length; i++) {
                    if (args[i].equals(name) && i + 1 < args.length) {
                        return args[i + 1];
                    }
                }
                return defaultValue;
            }

            private static boolean hasFlag(String[] args, String name) {
                for (String a : args) {
                    if (a.equals(name)) {
                        return true;
                    }
                }
                return false;
            }

            private static char[] readPassword(String prompt) throws IOException {
                Console console = System.console();
                if (console != null) {
                    return console.readPassword(prompt);
                }

                System.out.print(prompt + "(no console detected, input will be visible) ");
                System.out.flush();
                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
                String line = reader.readLine();
                return line == null ? new char[0] : line.toCharArray();
            }

            private static void printUsage() {
                System.out.println("""
                    vaultic - offline password manager with built-in TOTP (2FA) codes

                    usage:
                      vaultic init [--force]
                      vaultic add <site> [--user U] [--notes N] [--generate] [--length N] [--no-ambiguous]
                      vaultic get <site> [--show] [--clear-after SECONDS]
                      vaultic list [--filter TEXT]
                      vaultic remove <site> [--yes]
                      vaultic totp add <site> <base32-secret>
                      vaultic totp code <site>
                      vaultic generate [--length N] [--no-ambiguous]
                      vaultic passwd

                    global flags (any command):
                      --vault PATH           primary vault location (default: ~/.vaultic/vault.dat)
                      --backup-vault PATH    redundant copy location (default: ~/.vaultic-backup/vault.dat)
                      --no-backup            disable the backup copy entirely

                    note: the default backup lives on the same disk, so it only protects against
                    deleting one folder by accident. For real protection against a drive failure,
                    point --backup-vault at a different physical drive or a cloud-synced folder.
                    """);
            }
        }
    }
    }







