import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.io.*;

/**
 * NSA Codebreaker Challenge 2013 - Task 5
 *
 * For each password guess:
 *   1. key    = first 16 bytes of SHA-256(password)
 *   2. result = HMAC-SHA256(key, ciphertext)
 *   3. if result == TARGET_MAC  →  password found!
 *
 * COMPILE:  javac Breaking.java
 * RUN (with wordlist - RECOMMENDED):
 *           java Breaking rockyou.txt
 * RUN (built-in fallback):
 *           java Breaking
 */
public class Breaking {

    // ── 240-byte ciphertext from unk_416EC0 (IDA Pro dump) ──────────────────
    static final byte[] CIPHERTEXT = {
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

    // ── 32-byte target MAC from dword_416FB0 ─────────────────────────────────
    // (c) First two bytes = 0xBC, 0xB0
    static final byte[] TARGET_MAC = {
        (byte)0xBC,(byte)0xB0,(byte)0x78,(byte)0x41,(byte)0xAA,(byte)0xD0,(byte)0x06,(byte)0x68,
        (byte)0xDD,(byte)0xA4,(byte)0x74,(byte)0x06,(byte)0xD7,(byte)0x1A,(byte)0x2B,(byte)0xD2,
        (byte)0x9B,(byte)0x0E,(byte)0xDB,(byte)0x0D,(byte)0xF9,(byte)0xCE,(byte)0xF4,(byte)0xA7,
        (byte)0xF9,(byte)0x51,(byte)0x6C,(byte)0x99,(byte)0xFC,(byte)0xB6,(byte)0x95,(byte)0xF8
    };

    static MessageDigest sha256;
    static Mac hmacSha256;

    public static void main(String[] args) throws Exception {
        sha256    = MessageDigest.getInstance("SHA-256");
        hmacSha256 = Mac.getInstance("HmacSHA256");

        System.out.println("=== NSA Codebreaker 2013 - Task 5 ===");
        System.out.printf("(c) First two bytes of hash value: 0x%02X 0x%02X%n%n",
                TARGET_MAC[0], TARGET_MAC[1]);

        // ── Mode A: rockyou / any wordlist passed as argument ─────────────
        if (args.length > 0) {
            System.out.println("[*] Using wordlist: " + args[0]);
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(new FileInputStream(args[0]), "ISO-8859-1"))) {
                String line;
                long count = 0;
                while ((line = br.readLine()) != null) {
                    if (++count % 1_000_000 == 0)
                        System.out.printf("[*] Tried %,d passwords...%n", count);
                    if (tryPassword(line.trim())) return;
                }
            }
            System.out.println("[-] Password not found in wordlist.");
            return;
        }

        // ── Mode B: built-in fallback ─────────────────────────────────────
        System.out.println("[!] No wordlist provided.");
        System.out.println("[!] For best results: java Breaking rockyou.txt");
        System.out.println("[*] Running built-in search...\n");

        // 1. All numeric strings 1-8 digits
        System.out.println("[1] Numeric passwords (00 .. 99999999)...");
        for (int len = 1; len <= 8; len++) {
            String fmt = "%0" + len + "d";
            int max = (int) Math.pow(10, len);
            for (int i = 0; i < max; i++)
                if (tryPassword(String.format(fmt, i))) return;
        }

        // 2. Common English passwords (plain, UPPER, Capitalized)
        System.out.println("[2] Common passwords...");
        String[] words = {
            "password","secret","letmein","admin","qwerty","abc123","monkey",
            "dragon","master","sunshine","princess","welcome","shadow","baseball",
            "football","superman","batman","iloveyou","trustno1","passw0rd",
            "hello","access","test","guest","root","user","changeme","default",
            "temp","winter","summer","spring","autumn","hunter2","starwars",
            "solo","p@ssword","pa$$word","p@$$w0rd","security","nsa","cipher",
            "crypto","hacker","breaker","codebreak","agent","operative"
        };
        for (String w : words) {
            if (tryPassword(w)) return;
            if (tryPassword(w.toUpperCase())) return;
            if (w.length() > 0) {
                String cap = Character.toUpperCase(w.charAt(0)) + w.substring(1);
                if (tryPassword(cap)) return;
            }
            // common suffixes
            for (String sfx : new String[]{"1","123","!","2013","2012","1234"}) {
                if (tryPassword(w + sfx)) return;
                if (tryPassword(w.toUpperCase() + sfx)) return;
            }
        }

        // 3. All lowercase a-z up to length 5
        System.out.println("[3] Brute force lowercase a-z, length 1-5...");
        if (bruteForce("", "abcdefghijklmnopqrstuvwxyz", 5)) return;

        System.out.println("\n[-] Password not found in built-in search.");
        System.out.println("    Run: java Breaking rockyou.txt");
        System.out.println("    (rockyou.txt: ~14M real passwords, free via SecLists on GitHub)");
    }

    /**
     * Tests one password guess.
     * Steps: SHA-256(guess) -> take first 16 bytes as AES key
     *        -> HMAC-SHA256(key, CIPHERTEXT) -> compare to TARGET_MAC
     */
    static boolean tryPassword(String guess) throws Exception {
        if (guess.isEmpty()) return false;

        // Step 1: derive 16-byte AES key from password
        sha256.reset();
        byte[] hash = sha256.digest(guess.getBytes("UTF-8"));
        byte[] key16 = Arrays.copyOf(hash, 16);

        // Step 2: HMAC-SHA256(key, ciphertext)
        SecretKeySpec sks = new SecretKeySpec(key16, "AES");
        hmacSha256.init(sks);
        byte[] mac = hmacSha256.doFinal(CIPHERTEXT);

        // Step 3: compare
        if (Arrays.equals(mac, TARGET_MAC)) {
            System.out.println("\n╔══════════════════════════════════╗");
            System.out.println("║       *** FOUND IT! ***          ║");
            System.out.println("╚══════════════════════════════════╝");
            System.out.println("(d) Password       : \"" + guess + "\"");
            sha256.reset();
            byte[] fullHash = sha256.digest(guess.getBytes("UTF-8"));
            System.out.print("    SHA-256(password): ");
            for (byte b : fullHash) System.out.printf("%02X", b);
            System.out.printf("%n(c) First two bytes of SHA-256: 0x%02X 0x%02X%n",
                    fullHash[0], fullHash[1]);
            return true;
        }
        return false;
    }

    static boolean bruteForce(String prefix, String charset, int maxLen) throws Exception {
        if (!prefix.isEmpty() && tryPassword(prefix)) return true;
        if (prefix.length() == maxLen) return false;
        for (char c : charset.toCharArray())
            if (bruteForce(prefix + c, charset, maxLen)) return true;
        return false;
    }
}
