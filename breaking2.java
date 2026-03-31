import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class breaking2
{
    public static void main(String[] args) throws Exception
    {
        byte[] CIPHERTEXT = {
            (byte)0x34,(byte)0x3B,(byte)0x71,(byte)0x62,(byte)0xBA,(byte)0x9F,(byte)0x55,(byte)0xB8,(byte)0xD9,(byte)0x88,
            (byte)0x71,(byte)0x98,(byte)0x24,(byte)0x41,(byte)0x3E,(byte)0x4D,(byte)0xA4,(byte)0xBD,(byte)0x1A,(byte)0xE1,
            (byte)0x2C,(byte)0xAE,(byte)0x2C,(byte)0xFF,(byte)0x1D,(byte)0x4E,(byte)0x1A,(byte)0x9E,(byte)0x94,(byte)0x8A,
            (byte)0x4D,(byte)0x07,(byte)0x71,(byte)0x5D,(byte)0xC6,(byte)0x1F,(byte)0xEF,(byte)0x91,(byte)0x09,(byte)0x67,
            (byte)0xDA,(byte)0xFA,(byte)0x37,(byte)0x96,(byte)0x11,(byte)0xE1,(byte)0x67,(byte)0xD6,(byte)0x3E,(byte)0xA1,
            (byte)0x5E,(byte)0x58,(byte)0x0B,(byte)0x81,(byte)0xDD,(byte)0xB2,(byte)0xAF,(byte)0x5D,(byte)0xDE,(byte)0xDE,
            (byte)0x9D,(byte)0x82,(byte)0xB3,(byte)0x72,(byte)0x36,(byte)0x86,(byte)0xA6,(byte)0x72,(byte)0xEA,(byte)0x3E,
            (byte)0x5A,(byte)0xA0,(byte)0x21,(byte)0x4E,(byte)0x94,(byte)0xBF,(byte)0x51,(byte)0x12,(byte)0xBE,(byte)0xFC,
            (byte)0xB6,(byte)0x07,(byte)0x3D,(byte)0x51,(byte)0x36,(byte)0xCF,(byte)0x76,(byte)0x93,(byte)0xAB,(byte)0xC6,
            (byte)0x6C,(byte)0x7B,(byte)0x5F,(byte)0xC8,(byte)0x16,(byte)0xA2,(byte)0x11,(byte)0xC0,(byte)0xE6,(byte)0x87,
            (byte)0x9E,(byte)0xAB,(byte)0x40,(byte)0x56,(byte)0xA4,(byte)0xB7,(byte)0xA5,(byte)0x20,(byte)0x44,(byte)0xBF,
            (byte)0xB0,(byte)0xB7,(byte)0x5B,(byte)0x43,(byte)0x4A,(byte)0x02,(byte)0x19,(byte)0x09,(byte)0x1D,(byte)0xB2,
            (byte)0x30,(byte)0xBB,(byte)0x15,(byte)0xCE,(byte)0x1C,(byte)0x97,(byte)0xD8,(byte)0x77,(byte)0xBC,(byte)0x42,
            (byte)0x87,(byte)0x14,(byte)0x93,(byte)0x85,(byte)0xD2,(byte)0x0A,(byte)0x7D,(byte)0xC4,(byte)0x44,(byte)0x0E,
            (byte)0x82,(byte)0x35,(byte)0x3B,(byte)0xC4,(byte)0x40,(byte)0x78,(byte)0x7A,(byte)0x59,(byte)0xA1,(byte)0x59,
            (byte)0x18,(byte)0x09,(byte)0x22,(byte)0x17,(byte)0x68,(byte)0xC0,(byte)0xFC,(byte)0x7A,(byte)0x5F,(byte)0x67,
            (byte)0x5B,(byte)0x2A,(byte)0xB3,(byte)0xFC,(byte)0x53,(byte)0xBC,(byte)0xE0,(byte)0x92,(byte)0xFF,(byte)0x0D,
            (byte)0x84,(byte)0x74,(byte)0x31,(byte)0x1F,(byte)0xF5,(byte)0x16,(byte)0x4F,(byte)0x17,(byte)0x50,(byte)0x8D,
            (byte)0x95,(byte)0x51,(byte)0x06,(byte)0xF7,(byte)0xBC,(byte)0xDA,(byte)0x15,(byte)0x05,(byte)0x76,(byte)0xB5,
            (byte)0x10,(byte)0x78,(byte)0xA4,(byte)0xA1,(byte)0xF1,(byte)0x45,(byte)0xF1,(byte)0x6E,(byte)0x78,(byte)0x2C,
            (byte)0x3A,(byte)0x01,(byte)0x4E,(byte)0x82,(byte)0x68,(byte)0x4F,(byte)0xE8,(byte)0x12,(byte)0x69,(byte)0xDD,
            (byte)0x00,(byte)0x77,(byte)0x17,(byte)0xEC,(byte)0x95,(byte)0x76,(byte)0xBC,(byte)0x8C,(byte)0x43,(byte)0xC5,
            (byte)0x99,(byte)0x53,(byte)0xBA,(byte)0x86,(byte)0x4C,(byte)0x6B,(byte)0x46,(byte)0x4A,(byte)0x35,(byte)0x82,
            (byte)0xE1,(byte)0x10,(byte)0xEE,(byte)0x2A,(byte)0x73,(byte)0x4D,(byte)0x80,(byte)0x55,(byte)0xDC,(byte)0xBC,
        };

        // 32-byte target MAC from dword_416FB0
        byte[] TARGET_MAC = {
            (byte)0xBC,(byte)0xB0,(byte)0x78,(byte)0x41,(byte)0xAA,(byte)0xD0,(byte)0x06,(byte)0x68,
            (byte)0xDD,(byte)0xA4,(byte)0x74,(byte)0x06,(byte)0xD7,(byte)0x1A,(byte)0x2B,(byte)0xD2,
            (byte)0x9B,(byte)0x0E,(byte)0xDB,(byte)0x0D,(byte)0xF9,(byte)0xCE,(byte)0xF4,(byte)0xA7,
            (byte)0xF9,(byte)0x51,(byte)0x6C,(byte)0x99,(byte)0xFC,(byte)0xB6,(byte)0x95,(byte)0xF8
        };
        
        byte foundV0 = 0, foundV1 = 0;
        boolean found = false;

        outer:
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 256; j++) {
                byte v0 = (byte) i;
                byte v1 = (byte) j;
                byte[] key = deriveKey(v0, v1);
                byte[] mac = hmacSha256(key, CIPHERTEXT);
                if (Arrays.equals(mac, TARGET_MAC)) {
                    foundV0 = v0;
                    foundV1 = v1;
                    found = true;
                    break outer;
                }
            }
        }
        System.out.println("Done brute force.");

        if (!found) {
            System.out.println("No match found — double-check your CIPHERTEXT and MAC bytes against IDA.");
            return;
        }

        String password = findPassword(foundV0, foundV1);
        if (password != null) {
            System.out.println("Password found: " + password);
            byte[] h = sha256Bytes(password);
            System.out.printf("Verify SHA-256[0]=%02X [1]=%02X%n", h[0] & 0xFF, h[1] & 0xFF);
        } else {
            System.out.println("Password not found — try expanding the search space.");
        }
    }

    // ── PASSWORD SEARCH ───────────────────────────────────────────────────────
    public static String findPassword(byte v0, byte v1) throws Exception {
        String[] common = {
            "password","123456","abc123","letmein","monkey","dragon","master",
            "sunshine","princess","welcome","shadow","ninja","mustang",
            "password1","test","admin","login","pass","hello","secret",
            "god","love","sex","money","1234","12345","1234567","12345678",
            "qwerty","baseball","iloveyou","trustno1","superman","batman",
            "access","michael","jessica","ranger","maverick","football",
            "charlie","thomas","andrew","tigger","soccer","hockey","harley"
        };
        for (String pw : common) {
            if (matchesHashBytes(pw, v0, v1)) return pw;
        }
        String chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        for (int len = 1; len <= 6; len++) {
            System.out.println("  Trying length " + len + "...");
            String r = bruteForce("", len, chars, v0, v1);
            if (r != null) return r;
        }
        return null;
    }

    public static String bruteForce(String prefix, int remaining, String chars, byte v0, byte v1) throws Exception {
        if (remaining == 0) return matchesHashBytes(prefix, v0, v1) ? prefix : null;
        for (int i = 0; i < chars.length(); i++) {
            String r = bruteForce(prefix + chars.charAt(i), remaining - 1, chars, v0, v1);
            if (r != null) return r;
        }
        return null;
    }

    public static boolean matchesHashBytes(String pw, byte v0, byte v1) throws Exception {
        byte[] h = sha256Bytes(pw);
        return h[0] == v0 && h[1] == v1;
    }

    // ── CRYPTO ────────────────────────────────────────────────────────────────
    public static byte[] sha256Bytes(String password) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256")
                            .digest(password.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        SecretKeySpec sks = new SecretKeySpec(key, "AES");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(sks);
        return mac.doFinal(data);
    }

    public static byte[] deriveKey(byte v0, byte v1) {
        byte[] k = new byte[16];
        k[0]  = xor(v1,   0x23);
        k[1]  = xor(v0,   0x8E);
        k[2]  = xor(k[1], 0x60);
        k[3]  = xor(k[0], 0xE1);
        k[4]  = xor(k[3], 0xD2);
        k[5]  = xor(k[2], 0x96);
        k[6]  = xor(k[5], 0x38);
        k[7]  = xor(k[4], 0xC7);
        k[8]  = xor(k[7], 0xA5);
        k[9]  = xor(k[6], 0xC0);
        k[10] = xor(k[9], 0x22);
        k[11] = xor(k[8], 0x74);
        k[12] = xor(k[11], 0x4F);
        k[13] = xor(k[10], 0x31);
        k[14] = xor(k[13], 0x5B);
        k[15] = xor(k[12], 0xCD);
        return k;
    }

    public static byte xor(byte v, int c) { return (byte)((v ^ c) & 0xFF); }

    public static String toHex(byte[] d) {
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02X", b & 0xFF));
        return sb.toString();
    }

    public static String byteToHex(byte b) { return String.format("%02X", b & 0xFF); }
}