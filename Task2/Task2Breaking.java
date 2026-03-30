package Task2;

import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class Task2Breaking {

    static final byte[] CIPHERTEXT = new byte[] {
        (byte)0x92, (byte)0x4B, (byte)0x51, (byte)0xE7, (byte)0x80, (byte)0x90, (byte)0xF7, (byte)0x07, (byte)0x4D, (byte)0xE6, (byte)0x0E,
        (byte)0x1F, (byte)0x9C, (byte)0x85, (byte)0x1D, (byte)0x7A, (byte)0x32, (byte)0xB6, (byte)0xE2, (byte)0x8F, (byte)0x9B,
        (byte)0x13, (byte)0x53, (byte)0x79, (byte)0x33, (byte)0x76, (byte)0x4C, (byte)0x59, (byte)0x2D, (byte)0x44, (byte)0x57, (byte)0xDD,
        (byte)0x10, (byte)0x92, (byte)0x55, (byte)0x93, (byte)0x68, (byte)0x52, (byte)0xF2, (byte)0x3E, (byte)0xC3, (byte)0x58,
        (byte)0xB9, (byte)0x96, (byte)0x46, (byte)0x80, (byte)0x17, (byte)0x64, (byte)0x44, (byte)0x08, (byte)0xC6, (byte)0x28, (byte)0xCC,
        (byte)0x7B, (byte)0x02, (byte)0x8B, (byte)0x4A, (byte)0x5F, (byte)0xE5, (byte)0x6D, (byte)0xE8, (byte)0xF1, (byte)0xD2,
        (byte)0x08, (byte)0x47, (byte)0x4B, (byte)0x4E, (byte)0xDF, (byte)0x0A, (byte)0x13, (byte)0x18, (byte)0x52, (byte)0x30, (byte)0x6B,
        (byte)0xB2, (byte)0x83, (byte)0xE7, (byte)0x08, (byte)0x9A, (byte)0x57, (byte)0xD5, (byte)0xA5, (byte)0x18, (byte)0x34,
        (byte)0x9F, (byte)0xCE, (byte)0xAE, (byte)0x54, (byte)0xC1, (byte)0x63, (byte)0x56, (byte)0x03, (byte)0xBE, (byte)0xD8,
        (byte)0x91, (byte)0x29, (byte)0x85, (byte)0x93, (byte)0xA2, (byte)0x9D, (byte)0x12, (byte)0xE9, (byte)0x22, (byte)0x0A,
        (byte)0xCB, (byte)0x0D, (byte)0xC4, (byte)0xDB, (byte)0xAF, (byte)0x7A, (byte)0x75, (byte)0x6F, (byte)0x35, (byte)0x11,
        (byte)0x37, (byte)0x0C, (byte)0x40, (byte)0xA5, (byte)0x89, (byte)0x3D, (byte)0xCA, (byte)0xA5, (byte)0x9C, (byte)0x99,
        (byte)0x92, (byte)0xF0, (byte)0xE1, (byte)0x99, (byte)0x6D, (byte)0x86, (byte)0xCE, (byte)0x25, (byte)0xE4, (byte)0x8D,
        (byte)0x06, (byte)0xC0, (byte)0x9E, (byte)0x36, (byte)0xFD, (byte)0x25, (byte)0x29, (byte)0x59, (byte)0x6D, (byte)0xD9, (byte)0x22,
        (byte)0xA4, (byte)0xB4, (byte)0x36, (byte)0x37, (byte)0x4C, (byte)0x71, (byte)0xED, (byte)0xD8, (byte)0xEA, (byte)0x53,
        (byte)0x45, (byte)0x3D, (byte)0xA2, (byte)0xC5, (byte)0x9A, (byte)0x95, (byte)0xC4, (byte)0xB4, (byte)0xC9, (byte)0x02,
        (byte)0x5D, (byte)0x37, (byte)0x3F, (byte)0x80, (byte)0xA5, (byte)0x92, (byte)0xEB, (byte)0x32, (byte)0x2A, (byte)0xA7,
        (byte)0x05, (byte)0xAC, (byte)0xE5, (byte)0x54, (byte)0xEE, (byte)0xB7, (byte)0xAB, (byte)0x6F, (byte)0x8E, (byte)0x4D,
        (byte)0xA2, (byte)0x24, (byte)0x68, (byte)0xA0, (byte)0x31, (byte)0xFC, (byte)0x2D, (byte)0xF9, (byte)0xF0, (byte)0xFD,
        (byte)0x8E, (byte)0x28, (byte)0xA1, (byte)0x67, (byte)0xB3, (byte)0xE3, (byte)0x95, (byte)0xA0, (byte)0x73, (byte)0xAE,
        (byte)0xB7, (byte)0xE8, (byte)0x93, (byte)0x56, (byte)0x51, (byte)0x7E, (byte)0xDC, (byte)0xAA, (byte)0xBD, (byte)0x9D,
        (byte)0x45, (byte)0x08, (byte)0xA5, (byte)0x35, (byte)0x1D, (byte)0xC4, (byte)0xBC, (byte)0x03, (byte)0x33, (byte)0x03, (byte)0x96,
        (byte)0x88, (byte)0x7F, (byte)0x00, (byte)0x08, (byte)0x9E, (byte)0x9C, (byte)0xEC, (byte)0xD1, (byte)0x37, (byte)0x4D, (byte)0x40,
        (byte)0x86, (byte)0xCE, (byte)0x2D
    };

    static final byte[] TARGET_MAC = {
        (byte)0x66, (byte)0x95, (byte)0x67, (byte)0x02, (byte)0xBD, (byte)0xD4, (byte)0x5F, (byte)0x72, (byte)0x49, (byte)0xF8, (byte)0xBB,
        (byte)0x59, (byte)0x5B, (byte)0xB3, (byte)0xC5, (byte)0x9A, (byte)0xE1, (byte)0x59, (byte)0xC7, (byte)0x9E, (byte)0xCD,
        (byte)0x9F, (byte)0x72, (byte)0x31, (byte)0xDB, (byte)0x7B, (byte)0x6A, (byte)0x92, (byte)0xEE, (byte)0xF6, (byte)0x27,
        (byte)0x32
    };

static final byte[] CHARSET = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~".getBytes();

    static volatile boolean found = false;

    public static void main(String[] args) throws Exception {
        int maxLen = 6;
        int numThreads = Runtime.getRuntime().availableProcessors();
        System.out.println("Using " + numThreads + " threads, charset size: " + CHARSET.length);

        for (int len = 1; len <= maxLen && !found; len++) {
            final int L = len;
            System.out.println("Trying length: " + len);

            Thread[] threads = new Thread[numThreads];
            int chunkSize = (CHARSET.length + numThreads - 1) / numThreads;

            for (int t = 0; t < numThreads; t++) {
                final int startIdx = t * chunkSize;
                final int endIdx = Math.min(startIdx + chunkSize, CHARSET.length);
                if (startIdx >= CHARSET.length) break;

                threads[t] = new Thread(() -> {
                    try {
                        MessageDigest md = MessageDigest.getInstance("SHA-256");
                        Mac mac = Mac.getInstance("HmacSHA256");
                        byte[] attempt = new byte[L];
                        byte[] key = new byte[16];

                        for (int fi = startIdx; fi < endIdx && !found; fi++) {
                            attempt[0] = CHARSET[fi];
                            for (int i = 1; i < L; i++) attempt[i] = CHARSET[0];
                            bruteForce(attempt, 1, L, md, mac, key);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
                threads[t].start();
            }

            for (Thread t : threads) if (t != null) t.join();
        }

        if (!found) System.out.println("Password not found.");
    }

    static void bruteForce(byte[] attempt, int pos, int len,
                           MessageDigest md, Mac mac, byte[] key) throws Exception {
        if (found) return;

        if (pos == len) {
            md.reset();
            byte[] pwdHash = md.digest(attempt);
            System.arraycopy(pwdHash, 0, key, 0, 16);

            // Use "AES" as per the assignment spec
            SecretKeySpec sks = new SecretKeySpec(key, "AES");
            mac.init(sks);
            byte[] result = mac.doFinal(CIPHERTEXT);

            if (Arrays.equals(result, TARGET_MAC)) {
                found = true;
                System.out.println("Password found: " + new String(attempt, "UTF-8"));
                System.out.printf("First two bytes of hash: 0x%02X 0x%02X%n",
                    pwdHash[0], pwdHash[1]);
            }
            return;
        }

        for (byte c : CHARSET) {
            if (found) return;
            attempt[pos] = c;
            bruteForce(attempt, pos + 1, len, md, mac, key);
        }
    }
}