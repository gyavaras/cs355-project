import java.util.concurrent.CountDownLatch;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;

public class Server {
    private final byte[] encryptionKey; // Key used for decryption
    private final byte[] macKey; // Key used for HMAC verification
    private Client.EncryptedData aliceData; // Encrypted data received from Alice
    private Client.EncryptedData bobData; // Encrypted data received from Bob
    private final CountDownLatch latch; // Synchronizer to wait for both clients

    /**
     * Constructor for the Server class.
     *
     * @param encryptionKey The AES encryption key.
     * @param macKey        The HMAC key.
     * @param clientCount   The number of clients (should be 2 for Alice and Bob).
     */
    public Server(byte[] encryptionKey, byte[] macKey, int clientCount) {
        this.encryptionKey = encryptionKey;
        this.macKey = macKey;
        this.latch = new CountDownLatch(clientCount);
    }

    /**
     * Receives encrypted data from a client.
     * This method is synchronized to handle concurrent access.
     *
     * @param client The client sending the data (either Alice or Bob).
     * @param data   The encrypted data from the client.
     */
    public synchronized void receiveDataFromClient(Client client, Client.EncryptedData data) {
        if (client instanceof Alice) {
            aliceData = data;
        } else if (client instanceof Bob) {
            bobData = data;
        }
        latch.countDown();
    }

    /**
     * Starts the comparison of data from both clients.
     * This method waits until both clients have sent their data.
     *
     * @throws InterruptedException if the current thread is interrupted while waiting.
     */
    public void startComparison() throws InterruptedException {
        latch.await(); // Wait for both clients to send their data
        compare(aliceData, bobData);
    }

    /**
     * Compares the encrypted data received from both clients.
     *
     * @param data1 Encrypted data from the first client.
     * @param data2 Encrypted data from the second client.
     */
    private void compare(Client.EncryptedData data1, Client.EncryptedData data2) {
        try {
            byte[] decryptedData1 = decryptAndVerifyHMAC(data1);
            byte[] decryptedData2 = decryptAndVerifyHMAC(data2);

            if (decryptedData1 != null && decryptedData2 != null) {
                if (Arrays.equals(decryptedData1, decryptedData2)) {
                    System.out.println("The server determined that the two clients have the same code segment.");
                } else {
                    System.out.println("The server determined that the two clients do not have the same code segment.");
                }
            } else {
                System.out.println("HMAC verification failed. Cannot compare the data.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Decrypts the data and verifies the HMAC.
     *
     * @param data The encrypted data with HMAC.
     * @return Decrypted data if HMAC is verified, null otherwise.
     * @throws Exception if an error occurs during decryption or HMAC verification.
     */
    private byte[] decryptAndVerifyHMAC(Client.EncryptedData data) throws Exception {
        if (verifyHmac(data.getHmac(), macKey, data.getEncryptedData())) {
            return decrypt(encryptionKey, data.getIv().getIV(), data.getEncryptedData());
        } else {
            return null;
        }
    }

    /**
     * Verifies the HMAC of the given data.
     *
     * @param hmac The HMAC to be verified.
     * @param key  The key used for HMAC generation.
     * @param data The original data.
     * @return true if the HMAC is valid, false otherwise.
     * @throws Exception if an error occurs during HMAC verification.
     */
    private boolean verifyHmac(byte[] hmac, byte[] key, byte[] data) throws Exception {
        Mac hmacInstance = Mac.getInstance(Client.HASH_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, Client.HASH_ALGORITHM);
        hmacInstance.init(secretKeySpec);
        byte[] expectedHmac = hmacInstance.doFinal(data);
        return Arrays.equals(expectedHmac, hmac);
    }

    /**
     * Decrypts the given ciphertext using AES/CBC/PKCS5Padding.
     *
     * @param key        The AES key.
     * @param iv         The initialization vector.
     * @param ciphertext The ciphertext to be decrypted.
     * @return The decrypted plaintext.
     * @throws Exception if an error occurs during decryption.
     */
    private byte[] decrypt(byte[] key, byte[] iv, byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(Client.ENCRYPTION_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(ciphertext);
    }
}
