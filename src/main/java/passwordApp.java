import org.w3c.dom.ls.LSOutput;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.sql.SQLOutput;
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





}
