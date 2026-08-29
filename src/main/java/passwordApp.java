import org.w3c.dom.ls.LSOutput;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.sql.SQLOutput;
import java.util.Arrays;
import java.util.Locale;

public final class passwordApp {

    public static void main(String[] args) {
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
            // Deliberately new SecureRandom(), not getInstanceStrong() - the
            // "strong" variant can block on some Linux setups waiting on
            // OS entropy and has hung CLI tools mid-demo. This is still
            // fully cryptographically secure.
            new SecureRandom().nextBytes(b);
            return b;
        }
    }



}
