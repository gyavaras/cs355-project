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

    // Server method to compare encrypted hashes
    private static void compareEncryptedHashes(byte[] aliceEncryptedHash, byte[] aliceHmac, byte[] bobEncryptedHash, byte[] bobHmac, byte[] key, IvParameterSpec aliceIv, IvParameterSpec bobIv) throws Exception {
        // Verify HMACs before decrypting
        if (verifyHmac(aliceHmac, key, aliceEncryptedHash) && verifyHmac(bobHmac, key, bobEncryptedHash)) {
            // Decrypt both hashes
            byte[] aliceDecryptedHash = decrypt(key, aliceIv.getIV(), aliceEncryptedHash);
            byte[] bobDecryptedHash = decrypt(key, bobIv.getIV(), bobEncryptedHash);

            // Compare decrypted hashes
            if (Arrays.equals(aliceDecryptedHash, bobDecryptedHash)) {
                System.out.println("The server determined that Alice and Bob have the same code segment.");
            } else {
                System.out.println("The server determined that Alice and Bob do not have the same code segment.");
            }
        } else {
            System.out.println("The server could not verify one or both HMACs.");
        }
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

            // Alice and Bob send their encrypted hashes and HMACs to the server
            // For demonstration, we call the server method directly
            compareEncryptedHashes(aliceEncryptedHash, aliceHmac, bobEncryptedHash, bobHmac, encryptionKey, aliceIv, bobIv);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

