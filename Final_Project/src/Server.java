import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.DataInputStream;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

public class Server {
    private final byte[] encryptionKey;
    private final byte[] macKey;
    private Client.EncryptedData aliceData;
    private Client.EncryptedData bobData;
    private final CountDownLatch latch;
    private ConcurrentHashMap<String, Client.EncryptedData> clientDataMap;

    private int port;
    public Server(byte[] encryptionKey, byte[] macKey, int clientCount, int port) {
        this.encryptionKey = encryptionKey;
        this.macKey = macKey;
        this.latch = new CountDownLatch(clientCount);
        this.port = port;
        this.clientDataMap = new ConcurrentHashMap<>();
    }

    public void startServer() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (latch.getCount() > 0) {
                Socket clientSocket = serverSocket.accept();
                new Thread(new ClientHandler(clientSocket)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    private class ClientHandler implements Runnable {
        private Socket clientSocket;

        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
        }

        public void run() {
            try (DataInputStream dis = new DataInputStream(clientSocket.getInputStream())) {
                byte[] iv = Base64.getDecoder().decode(dis.readUTF());
                byte[] encryptedData = Base64.getDecoder().decode(dis.readUTF());
                byte[] hmac = Base64.getDecoder().decode(dis.readUTF());
                String clientId = dis.readUTF();

                Client.EncryptedData data = new Client.EncryptedData(encryptedData, hmac, new IvParameterSpec(iv));
                clientDataMap.put(clientId, data);
                latch.countDown();

                if (latch.getCount() == 0) {
                    compareData();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }



    private void compareData() {
        try {
            // Retrieve encrypted data for both clients
            Client.EncryptedData aliceData = clientDataMap.get("Alice");
            Client.EncryptedData bobData = clientDataMap.get("Bob");

            // Decrypt and verify HMAC for both clients' data
            byte[] aliceDecryptedData = decryptAndVerifyHMAC(aliceData);
            byte[] bobDecryptedData = decryptAndVerifyHMAC(bobData);

            if (aliceDecryptedData != null && bobDecryptedData != null) {
                // Compare decrypted data
                if (Arrays.equals(aliceDecryptedData, bobDecryptedData)) {
                    System.out.println("The server determined that Alice and Bob have the same code segment.");
                } else {
                    System.out.println("The server determined that Alice and Bob do not have the same code segment.");
                }
            } else {
                System.out.println("HMAC verification failed for one or both clients. Cannot compare the data.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("An error occurred while comparing data.");
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
