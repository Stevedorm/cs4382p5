import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

MessageDigest md = MessageDigest.getInstance("SHA-256");
byte[] hash = md.digest(aGuessedPassword.getBytes());

SecretKeySpec sks = new SecretKeySpec(key, "AES");

Mac mac = Mac.getInstance("HmacSHA256");
mac.init(sks);
byte[] hmac = mac.doFinal(embeddedCiphertext);