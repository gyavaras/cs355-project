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


public class Server {
    // Encryption and MAC keys for secure communication
    private final byte[] encryptionKey;
    private final byte[] macKey;
    // Lists to store encrypted data from Alice and Bob
    private List<Client.EncryptedData> aliceDataList = new ArrayList<>();
    private List<Client.EncryptedData> bobDataList = new ArrayList<>();
    // Countdown latch to synchronize client threads
    private final CountDownLatch latch;

    // ServerSocket to accept client connections
    private ServerSocket serverSocket;
    // Thread pool for handling multiple clients concurrently
    private ExecutorService pool;
    // Flag to track if any matching data is found during comparison
    private boolean anyMatchFound = false;
    // Number of expected clients
    private final int clientCount;

    // Constructor to initialize the server with keys and client count
    public Server(byte[] encryptionKey, byte[] macKey, int clientCount) throws IOException {
        this.encryptionKey = encryptionKey;
        this.macKey = macKey;
        this.latch = new CountDownLatch(clientCount);
        this.serverSocket = new ServerSocket(12345); // Use an appropriate port number
        this.pool = Executors.newFixedThreadPool(clientCount);
        this.clientCount = clientCount;
    }

    // Method to start the server, accept client connections, and initiate data comparison
    public void startServer() {
        //System.out.println("Server is running...");
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
    // Method to receive encrypted data from clients
    public synchronized void receiveDataFromClient(String clientId, Client.EncryptedData data) {
        if ("Alice".equals(clientId)) {
            aliceDataList.add(data);
        } else if ("Bob".equals(clientId)) {
            bobDataList.add(data);
        }
    }
    // Method to initiate the comparison of encrypted data from Alice and Bob
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
    // Method to initiate the comparison of encrypted data from Alice and Bob
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
    // Method to decrypt and verify HMAC of the encrypted data
    private byte[] decryptAndVerifyHMAC(Client.EncryptedData data) throws Exception {
        if (verifyHmac(data.getHmac(), macKey, data.getEncryptedData())) {
            IvParameterSpec ivParameterSpec = data.getIvParameterSpec(); // Convert byte array to IvParameterSpec
            return decrypt(encryptionKey, ivParameterSpec.getIV(), data.getEncryptedData());
        } else {
            return null;
        }
    }
    // Method to verify HMAC using provided key and data
    private boolean verifyHmac(byte[] hmac, byte[] key, byte[] data) throws Exception {
        Mac hmacInstance = Mac.getInstance(Client.HASH_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, Client.HASH_ALGORITHM);
        hmacInstance.init(secretKeySpec);
        byte[] expectedHmac = hmacInstance.doFinal(data);
        return Arrays.equals(expectedHmac, hmac);
    }
    // Method to decrypt data using AES algorithm
    private byte[] decrypt(byte[] key, byte[] iv, byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(Client.ENCRYPTION_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(ciphertext);
    }
    // Method to shut down the server gracefully
    private void shutdownServer() {
        try {
            pool.shutdown();
            serverSocket.close();
            //System.out.println("Server shut down.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    // Inner class representing a thread to handle communication with a single client
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
