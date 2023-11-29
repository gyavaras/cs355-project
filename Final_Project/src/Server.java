import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher; // For doFinal method in Cipher class
import javax.crypto.spec.IvParameterSpec;

import java.io.InputStream;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.DigestInputStream; // If you're using DigestInputStream for hashing
import java.security.MessageDigest;

public class Server {
    private final byte[] encryptionKey;
    private final byte[] macKey;
    private List<Client.EncryptedData> aliceDataList = new ArrayList<>();
    private List<Client.EncryptedData> bobDataList = new ArrayList<>();
    private final CountDownLatch latch;

    private ServerSocket serverSocket;
    private ExecutorService pool;
    private boolean anyMatchFound = false;
    private final int clientCount;

    public Server(byte[] encryptionKey, byte[] macKey, int clientCount) throws IOException {
        this.encryptionKey = encryptionKey;
        this.macKey = macKey;
        this.latch = new CountDownLatch(clientCount);
        this.serverSocket = new ServerSocket(12345); // Use an appropriate port number
        this.pool = Executors.newFixedThreadPool(clientCount);
        this.clientCount = clientCount;
    }

    public void startServer() {
        System.out.println("Server is running...");
        int connectedClients = 0;

        while (connectedClients < clientCount) {
            try {
                Socket clientSocket = serverSocket.accept();
                //System.out.println("Client connected: " + clientSocket.getInetAddress());
                pool.execute(new ClientHandler(clientSocket));  // Only pass the clientSocket
                connectedClients++;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        try {
            latch.await(); // Wait for all client data transmissions to complete
            startComparison(); // Start the comparison after all clients are done
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            e.printStackTrace();
        }

        shutdownServer();
    }

    public synchronized void receiveDataFromClient(String clientId, Client.EncryptedData data) {
        if ("Alice".equals(clientId)) {
            aliceDataList.add(data);
        } else if ("Bob".equals(clientId)) {
            bobDataList.add(data);
        }
    }

    private void startComparison() throws InterruptedException {
        System.out.println("Starting comparison...");
        // Comparison logic
        for (Client.EncryptedData aliceData : aliceDataList) {
            for (Client.EncryptedData bobData : bobDataList) {
                compare(aliceData, bobData);
            }
        }

        if (anyMatchFound) {
            System.out.println("At least one match found.");
        } else {
            System.out.println("No matches found.");
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
            IvParameterSpec ivParameterSpec = data.getIvParameterSpec(); // Convert byte array to IvParameterSpec
            return decrypt(encryptionKey, ivParameterSpec.getIV(), data.getEncryptedData());
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

    private void shutdownServer() {
        try {
            pool.shutdown();
            serverSocket.close();
            //System.out.println("Server shut down.");
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
            try (ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream())) {
                String clientId = (String) ois.readObject();
                //System.out.println("Client " + clientId + " connected.");

                Object object;
                while ((object = ois.readObject()) != null) {
                    if (object instanceof Client.EncryptedData) {
                        Client.EncryptedData data = (Client.EncryptedData) object;
                        receiveDataFromClient(clientId, data);  // Directly call the method of Server class
                    }
                }
                //System.out.println("Client " + clientId + " data transmission completed.");
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try {
                    clientSocket.close();
                    //System.out.println("Client socket closed.");
                } catch (IOException e) {
                    e.printStackTrace();
                }
                latch.countDown(); // Signal that this client has finished
            }
        }
    }
}
