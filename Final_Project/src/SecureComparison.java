
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class SecureComparison {



        private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
        private static final String HASH_ALGORITHM = "HmacSHA256";
        private static final int IV_SIZE = 16; // AES block size

        private static final SecureRandom secureRandom = new SecureRandom();

        // Hash the code segment using SHA-256
        private static byte[] hash(String codeSegment) throws Exception {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(codeSegment.getBytes("UTF-8"));
        }

        // Generate a random Initialization Vector (IV)
        private static IvParameterSpec generateIv() {
            byte[] iv = new byte[IV_SIZE];
            secureRandom.nextBytes(iv);
            return new IvParameterSpec(iv);
        }

        // Encrypt the hash using AES in CBC mode
        private static byte[] encrypt(byte[] key, byte[] iv, byte[] plaintext) throws Exception {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            return cipher.doFinal(plaintext);
        }

        // Decrypt the hash using AES in CBC mode
        private static byte[] decrypt(byte[] key, byte[] iv, byte[] ciphertext) throws Exception {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            return cipher.doFinal(ciphertext);
        }

        // Create HMAC of the ciphertext
        private static byte[] createHmac(byte[] key, byte[] data) throws Exception {
            Mac hmac = Mac.getInstance(HASH_ALGORITHM);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, HASH_ALGORITHM);
            hmac.init(secretKeySpec);
            return hmac.doFinal(data);
        }

        // Verify the HMAC of the ciphertext
        private static boolean verifyHmac(byte[] hmac, byte[] key, byte[] data) throws Exception {
            byte[] expectedHmac = createHmac(key, data);
            return Arrays.equals(expectedHmac, hmac);
        }

        public static void main(String[] args) {
            try {
                // Assume Alice and Bob have agreed upon these secret keys securely
                byte[] encryptionKey = "encryptionKey1234".getBytes(); // 16 bytes key for AES
                byte[] macKey = "macKey12345678901".getBytes(); // 16 bytes key for HMAC

                // Alice's code segment hash
                String aliceCodeSegment = "Alice's secret code segment";
                byte[] aliceHash = hash(aliceCodeSegment);

                // Bob's code segment hash
                String bobCodeSegment = "Bob's secret code segment";
                byte[] bobHash = hash(bobCodeSegment);

                // Alice encrypts her hash
                IvParameterSpec aliceIv = generateIv();
                byte[] aliceEncryptedHash = encrypt(encryptionKey, aliceIv.getIV(), aliceHash);
                byte[] aliceHmac = createHmac(macKey, aliceEncryptedHash);

                // Bob encrypts his hash
                IvParameterSpec bobIv = generateIv();
                byte[] bobEncryptedHash = encrypt(encryptionKey, bobIv.getIV(), bobHash);
                byte[] bobHmac = createHmac(macKey, bobEncryptedHash);

                // Normally Alice and Bob would send their encrypted hashes and HMACs to each other,
                // here we simulate this by directly verifying and decrypting.

                // Alice receives Bob's encrypted hash and HMAC
                if (verifyHmac(bobHmac, macKey, bobEncryptedHash)) {
                    byte[] decryptedBobHash = decrypt(encryptionKey, bobIv.getIV(), bobEncryptedHash);
                    System.out.println("Alice verified Bob's HMAC and decrypted his hash: " + Base64.getEncoder().encodeToString(decryptedBobHash));
                } else {
                    System.out.println("Alice could not verify Bob's HMAC.");
                }

                // Bob receives Alice's encrypted hash and HMAC
                if (verifyHmac(aliceHmac, macKey, aliceEncryptedHash)) {
                    byte[] decryptedAliceHash = decrypt(encryptionKey, aliceIv.getIV(), aliceEncryptedHash);
                    System.out.println("Bob verified Alice's HMAC and decrypted her hash: " + Base64.getEncoder().encodeToString(decryptedAliceHash));
                } else {
                    System.out.println("Bob could not verify Alice's HMAC.");
                }

                // They could now compare the decrypted hashes to see if they match.
                // ...

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

