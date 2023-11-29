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
        this.serverSocket = new ServerSocket(12345); // Our port number used for testing sockets
        this.pool = Executors.newFixedThreadPool(clientCount);
        this.clientCount = clientCount;
    }

    // Method to start the server, accept client connections, and start the data comparison
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
        } catch (InterruptedException e) { // We use this for error handling a problem with threads
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
        // Comparison logic (just makes sure it goes through all of Alice and Bobs data list)
        for (Client.EncryptedData aliceData : aliceDataList) {
            for (Client.EncryptedData bobData : bobDataList) {
                compare(aliceData, bobData);
            }
        }
        //Boolean that checks if a match was found during comparison
        if (anyMatchFound) {
            System.out.println("At least one match found.");
        } else {
            System.out.println("No matches found.");
        }
    }
    // Method to start the comparison of encrypted data from Alice and Bob
    private void compare(Client.EncryptedData data1, Client.EncryptedData data2) {
        try {
            byte[] decryptedData1 = decryptAndVerifyHMAC(data1);
            byte[] decryptedData2 = decryptAndVerifyHMAC(data2);
            //Main check logic that makes sure the files are not empty and the data is actually equal
            //Exploiting that after the files are compressed it is deterministic so they will be equal if files are equal
            if (decryptedData1 != null && decryptedData2 != null && Arrays.equals(decryptedData1, decryptedData2)) {
                anyMatchFound = true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    // Method to decrypt and verify HMAC of the encrypted data
    // It first checks to see if the data authenticity of the data is verified, then starts to decrypt
    private byte[] decryptAndVerifyHMAC(Client.EncryptedData data) throws Exception {
        if (verifyHmac(data.getHmac(), macKey, data.getEncryptedData())) {
            // This gets the IV from the encrypted data and converts it to byte array for decryption
            IvParameterSpec ivParameterSpec = data.getIvParameterSpec();
            return decrypt(encryptionKey, ivParameterSpec.getIV(), data.getEncryptedData());
        } else {
            return null;
        }
    }
    // Method to verify HMAC using provided key and data
    // Makes sure that the data hasn't been altered in any way
    private boolean verifyHmac(byte[] hmac, byte[] key, byte[] data) throws Exception {
        //Initializes the mac instance with the HMAC alg in the client class
        Mac hmacInstance = Mac.getInstance(Client.HASH_ALGORITHM);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, Client.HASH_ALGORITHM);

        //Initializes the mac instance with the secret key
        hmacInstance.init(secretKeySpec);
        // computes the hmac with the data
        byte[] expectedHmac = hmacInstance.doFinal(data);

        //makes sure the expected hmac matches the other so that there have been no changes
        return Arrays.equals(expectedHmac, hmac);
    }
    // Method to decrypt data using AES algorithm (In CBC mode)
    private byte[] decrypt(byte[] key, byte[] iv, byte[] ciphertext) throws Exception {
        //Initializes the cipher instance for AES decryption
        Cipher cipher = Cipher.getInstance(Client.ENCRYPTION_ALGORITHM);

        //Converts the secretkey from bytes to an object cuz that is required by the cipher
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        //Same for this except it initializes the cipher
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        //initializes with the two new objects for decryption
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(ciphertext);
    }
    // Method to shut down the server gracefully after the comparison has been done
    private void shutdownServer() {
        try {
            pool.shutdown();
            serverSocket.close();
            //System.out.println("Server shut down.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    // Inner class representing a thread to handle communication with one client at a time
    private class ClientHandler implements Runnable {
        private Socket clientSocket;

        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
        }

        //takes data from either alice or bob and processes it
        public void run() {
            try (ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream())) {
                //first reads the client id which should be first piece of data from the client
                String clientId = (String) ois.readObject();
                //System.out.println("Client " + clientId + " connected.");

                Object object;

                //reads objects from the client until there isn't any more
                while ((object = ois.readObject()) != null) {
                    //also makes sure that it is of the correct encrypted type
                    if (object instanceof Client.EncryptedData) {
                        Client.EncryptedData data = (Client.EncryptedData) object;
                        receiveDataFromClient(clientId, data);  // Directly call the method of Server class
                    }
                }
                //System.out.println("Client " + clientId + " data transmission completed.");
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                //just makes sure that the socket is closed once the data was completed
                try {
                    clientSocket.close();
                    //System.out.println("Client socket closed.");
                } catch (IOException e) {
                    e.printStackTrace();
                }
                latch.countDown(); // Signal that this client has finished by counting down
            }
        }
    }
}
