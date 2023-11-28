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
    // Encryption key used for decrypting client data
    private final byte[] encryptionKey;
    // Message Authentication Code (MAC) key for data integrity verification
    private final byte[] macKey;
    // Encrypted data received from the clients
    private Client.EncryptedData aliceData;
    private Client.EncryptedData bobData;
    // Countdown latch to synchronize client data reception
    private final CountDownLatch latch;
    // Map to store encrypted data for each client
    private ConcurrentHashMap<String, Client.EncryptedData> clientDataMap;
    // Port on which the server listens for client connections
    private int port;
    // Constructor to initialize the server with encryption and MAC keys, client count, and port
    public Server(byte[] encryptionKey, byte[] macKey, int clientCount, int port) {
        this.encryptionKey = encryptionKey;
        this.macKey = macKey;
        this.latch = new CountDownLatch(clientCount);
        this.port = port;
        this.clientDataMap = new ConcurrentHashMap<>();
    }
    // Method to start the server and handle client connections
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
    // Method to start the server and handle client connections
    private class ClientHandler implements Runnable {
        private Socket clientSocket;
        // Constructor to initialize the client socket
        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
        }
        // Run method to handle communication with the client
        public void run() {
            try (DataInputStream dis = new DataInputStream(clientSocket.getInputStream())) {
                // Read encrypted data, HMAC, and client ID from the client
                byte[] iv = Base64.getDecoder().decode(dis.readUTF());
                byte[] encryptedData = Base64.getDecoder().decode(dis.readUTF());
                byte[] hmac = Base64.getDecoder().decode(dis.readUTF());
                String clientId = dis.readUTF();

                // Create EncryptedData object and store it in the clientDataMap
                Client.EncryptedData data = new Client.EncryptedData(encryptedData, hmac, new IvParameterSpec(iv));
                clientDataMap.put(clientId, data);
                // Signal that data has been received from a client
                latch.countDown();

                // If all clients have sent their data, compare the data
                if (latch.getCount() == 0) {
                    compareData();
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }


    // Method to compare encrypted data from different clients
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
