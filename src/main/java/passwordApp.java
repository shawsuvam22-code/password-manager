import java.io.ByteArrayOutputStream;
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

}
