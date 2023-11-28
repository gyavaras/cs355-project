import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Server {
    private final byte[] encryptionKey;
    private final byte[] macKey;
    private List<Client.EncryptedData> aliceDataList = new ArrayList<>();
    private List<Client.EncryptedData> bobDataList = new ArrayList<>();
    private final CountDownLatch latch;

    // Field to track if any match is found
    private boolean anyMatchFound = false;

    public Server(byte[] encryptionKey, byte[] macKey, int clientCount) {
        this.encryptionKey = encryptionKey;
        this.macKey = macKey;
        this.latch = new CountDownLatch(clientCount);
    }

    public synchronized void receiveDataFromClient(Client client, Client.EncryptedData data) {
        if ("Alice".equals(client.getClientId())) {
            aliceDataList.add(data);
        } else if ("Bob".equals(client.getClientId())) {
            bobDataList.add(data);
        }
        latch.countDown();
    }

    public void startComparison() throws InterruptedException {
        latch.await();
        for (Client.EncryptedData aliceData : aliceDataList) {
            for (Client.EncryptedData bobData : bobDataList) {
                compare(aliceData, bobData);
            }
        }

        // Output the final comparison result
        if (anyMatchFound) {
            System.out.println("The server determined that at least one of Alice's files matches one of Bob's files.");
        } else {
            System.out.println("The server determined that none of Alice's files match any of Bob's files.");
        }
    }

    private void compare(Client.EncryptedData data1, Client.EncryptedData data2) {
        try {
            byte[] decryptedData1 = decryptAndVerifyHMAC(data1);
            byte[] decryptedData2 = decryptAndVerifyHMAC(data2);

            if (decryptedData1 != null && decryptedData2 != null && Arrays.equals(decryptedData1, decryptedData2)) {
                anyMatchFound = true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] decryptAndVerifyHMAC(Client.EncryptedData data) throws Exception {
        if (verifyHmac(data.getHmac(), macKey, data.getEncryptedData())) {
            return decrypt(encryptionKey, data.getIv().getIV(), data.getEncryptedData());
        } else {
            return null;
        }
    }

    private boolean verifyHmac(byte[] hmac, byte[] key, byte[] data) throws Exception {
        Mac hmacInstance = Mac.getInstance(Client.HASH_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, Client.HASH_ALGORITHM);
        hmacInstance.init(secretKeySpec);
        byte[] expectedHmac = hmacInstance.doFinal(data);
        return Arrays.equals(expectedHmac, hmac);
    }

    private byte[] decrypt(byte[] key, byte[] iv, byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(Client.ENCRYPTION_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(ciphertext);
    }
}
