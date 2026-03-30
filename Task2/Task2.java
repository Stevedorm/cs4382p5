package Task2;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Task2 {

    private static final byte[] CIPHERTEXT = {
        (byte)0x92, (byte)0x4B, (byte)0x51, (byte)0xE7, (byte)0x80, (byte)0x90, (byte)0xF7, (byte)0x07,
        (byte)0x4D, (byte)0xE6, (byte)0x0E, (byte)0x1F, (byte)0x9C, (byte)0x85, (byte)0x1D, (byte)0x7A,
        (byte)0x32, (byte)0xB6, (byte)0xE2, (byte)0x8F, (byte)0x9B, (byte)0x13, (byte)0x53, (byte)0x79,
        (byte)0x33, (byte)0x76, (byte)0x4C, (byte)0x59, (byte)0x2D, (byte)0x44, (byte)0x57, (byte)0xDD,
        (byte)0x10, (byte)0x92, (byte)0x55, (byte)0x93, (byte)0x68, (byte)0x52, (byte)0xF2, (byte)0x3E,
        (byte)0xC3, (byte)0x58, (byte)0xB9, (byte)0x96, (byte)0x46, (byte)0x80, (byte)0x17, (byte)0x64,
        (byte)0x44, (byte)0x08, (byte)0xC6, (byte)0x28, (byte)0xCC, (byte)0x7B, (byte)0x02, (byte)0x8B,
        (byte)0x4A, (byte)0x5F, (byte)0xE5, (byte)0x6D, (byte)0xE8, (byte)0xF1, (byte)0xD2, (byte)0x08,
        (byte)0x47, (byte)0x4B, (byte)0x4E, (byte)0xDF, (byte)0x0A, (byte)0x13, (byte)0x18, (byte)0x52,
        (byte)0x30, (byte)0x6B, (byte)0xB2, (byte)0x83, (byte)0xE7, (byte)0x08, (byte)0x9A, (byte)0x57,
        (byte)0xD5, (byte)0xA5, (byte)0x18, (byte)0x34, (byte)0x9F, (byte)0xCE, (byte)0xAE, (byte)0x54,
        (byte)0xC1, (byte)0x63, (byte)0x56, (byte)0x03, (byte)0xBE, (byte)0xD8, (byte)0x91, (byte)0x29,
        (byte)0x85, (byte)0x93, (byte)0xA2, (byte)0x9D, (byte)0x12, (byte)0xE9, (byte)0x22, (byte)0x0A,
        (byte)0xCB, (byte)0x0D, (byte)0xC4, (byte)0xDB, (byte)0xAF, (byte)0x7A, (byte)0x75, (byte)0x6F,
        (byte)0x35, (byte)0x11, (byte)0x37, (byte)0x0C, (byte)0x40, (byte)0xA5, (byte)0x89, (byte)0x3D,
        (byte)0xCA, (byte)0xA5, (byte)0x9C, (byte)0x99, (byte)0x92, (byte)0xF0, (byte)0xE1, (byte)0x99,
        (byte)0x6D, (byte)0x86, (byte)0xCE, (byte)0x25, (byte)0xE4, (byte)0x8D, (byte)0x06, (byte)0xC0,
        (byte)0x9E, (byte)0x36, (byte)0xFD, (byte)0x25, (byte)0x29, (byte)0x59, (byte)0x6D, (byte)0xD9,
        (byte)0x22, (byte)0xA4, (byte)0xB4, (byte)0x36, (byte)0x37, (byte)0x4C, (byte)0x71, (byte)0xED,
        (byte)0xD8, (byte)0xEA, (byte)0x53, (byte)0x45, (byte)0x3D, (byte)0xA2, (byte)0xC5, (byte)0x9A,
        (byte)0x95, (byte)0xC4, (byte)0xB4, (byte)0xC9, (byte)0x02, (byte)0x5D, (byte)0x37, (byte)0x3F,
        (byte)0x80, (byte)0xA5, (byte)0x92, (byte)0xEB, (byte)0x32, (byte)0x2A, (byte)0xA7, (byte)0x05,
        (byte)0xAC, (byte)0xE5, (byte)0x54, (byte)0xEE, (byte)0xB7, (byte)0xAB, (byte)0x6F, (byte)0x8E,
        (byte)0x4D, (byte)0xA2, (byte)0x24, (byte)0x68, (byte)0xA0, (byte)0x31, (byte)0xFC, (byte)0x2D,
        (byte)0xF9, (byte)0xF0, (byte)0xFD, (byte)0x8E, (byte)0x28, (byte)0xA1, (byte)0x67, (byte)0xB3,
        (byte)0xE3, (byte)0x95, (byte)0xA0, (byte)0x73, (byte)0xAE, (byte)0xB7, (byte)0xE8, (byte)0x93,
        (byte)0x56, (byte)0x51, (byte)0x7E, (byte)0xDC, (byte)0xAA, (byte)0xBD, (byte)0x9D, (byte)0x45,
        (byte)0x08, (byte)0xA5, (byte)0x35, (byte)0x1D, (byte)0xC4, (byte)0xBC, (byte)0x03, (byte)0x33,
        (byte)0x03, (byte)0x96, (byte)0x88, (byte)0x7F, (byte)0x00, (byte)0x08, (byte)0x9E, (byte)0x9C,
        (byte)0xEC, (byte)0xD1, (byte)0x37, (byte)0x4D, (byte)0x40, (byte)0x86, (byte)0xCE, (byte)0x2D
    };

    private static final byte[] TARGET_MAC = {
        (byte)0x66, (byte)0x95, (byte)0x67, (byte)0x02, (byte)0xBD, (byte)0xD4, (byte)0x5F, (byte)0x72,
        (byte)0x49, (byte)0xF8, (byte)0xBB, (byte)0x59, (byte)0x5B, (byte)0xB3, (byte)0xC5, (byte)0x9A,
        (byte)0xE1, (byte)0x59, (byte)0xC7, (byte)0x9E, (byte)0xCD, (byte)0x9F, (byte)0x72, (byte)0x31,
        (byte)0xDB, (byte)0x7B, (byte)0x6A, (byte)0x92, (byte)0xEE, (byte)0xF6, (byte)0x27, (byte)0x32
    };

    public static void main(String[] args) throws Exception {
        bruteForceKey();
    }

    private static void bruteForceKey() throws Exception {
        byte matchV0 = 0, matchV1 = 0;
        boolean found = false;

        search:
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 256; j++) {
                byte v0 = (byte) i;
                byte v1 = (byte) j;

                byte[] candidateKey = deriveKey(v0, v1);
                byte[] computedMac  = hmacSha256(candidateKey, CIPHERTEXT);

                if (Arrays.equals(computedMac, TARGET_MAC)) {
                    matchV0 = v0;
                    matchV1 = v1;
                    found   = true;
                    break search;
                }
            }
        }

        if (!found) return;

        searchForPassword(matchV0, matchV1);
    }

    private static void searchForPassword(byte v0, byte v1) throws Exception {
        String password = findPassword(v0, v1);

        if (password != null) {
            byte[] hash = sha256Bytes(password);
            System.out.println("Password found: " + password);
            System.out.println("Derived key   : " + toHex(deriveKey(v0, v1)));
            System.out.printf ("SHA-256[0] = %02X  SHA-256[1] = %02X%n", hash[0] & 0xFF, hash[1] & 0xFF);
        }
    }

    public static String findPassword(byte v0, byte v1) throws Exception {
        String charset = "abcdefghijklmnopqrstuvwxyz0123456789";

        for (int length = 1; length <= 6; length++) {
            String result = bruteForcePassword("", length, charset, v0, v1);
            if (result != null) return result;
        }

        return null;
    }

    public static String bruteForcePassword(String prefix, int remaining, String charset,
                                            byte v0, byte v1) throws Exception {
        if (remaining == 0) {
            return matchesHashBytes(prefix, v0, v1) ? prefix : null;
        }

        for (int i = 0; i < charset.length(); i++) {
            String attempt = prefix + charset.charAt(i);
            String result  = bruteForcePassword(attempt, remaining - 1, charset, v0, v1);
            if (result != null) return result;
        }

        return null;
    }

    public static boolean matchesHashBytes(String password, byte v0, byte v1) throws Exception {
        byte[] hash = sha256Bytes(password);
        return hash[0] == v0 && hash[1] == v1;
    }

    public static byte[] sha256Bytes(String password) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256")
                            .digest(password.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "AES"));
        return mac.doFinal(data);
    }

    public static byte[] deriveKey(byte v0, byte v1) {
        byte[] k = new byte[16];

        k[0]  = xor(v1,    0x23);
        k[1]  = xor(v0,    0x8E);
        k[2]  = xor(k[1],  0x60);
        k[3]  = xor(k[0],  0xE1);
        k[4]  = xor(k[3],  0xD2);
        k[5]  = xor(k[2],  0x96);
        k[6]  = xor(k[5],  0x38);
        k[7]  = xor(k[4],  0xC7);
        k[8]  = xor(k[7],  0xA5);
        k[9]  = xor(k[6],  0xC0);
        k[10] = xor(k[9],  0x22);
        k[11] = xor(k[8],  0x74);
        k[12] = xor(k[11], 0x4F);
        k[13] = xor(k[10], 0x31);
        k[14] = xor(k[13], 0x5B);
        k[15] = xor(k[12], 0xCD);

        return k;
    }

    public static byte xor(byte value, int constant) {
        return (byte) ((value ^ constant) & 0xFF);
    }

    public static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) sb.append(String.format("%02X", b & 0xFF));
        return sb.toString();
    }

    public static String byteToHex(byte b) {
        return String.format("%02X", b & 0xFF);
    }
}