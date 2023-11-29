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
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;


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
        this.serverSocket = new ServerSocket(12345);
        this.pool = Executors.newFixedThreadPool(clientCount);
        this.clientCount = clientCount;
    }

    public void startServer() {
        int connectedClients = 0;

        while (connectedClients < clientCount) {
            try {
                Socket clientSocket = serverSocket.accept();
                pool.execute(new ClientHandler(clientSocket));
                connectedClients++;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        try {
            latch.await();
            startComparison();
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

        for (Client.EncryptedData aliceData : aliceDataList) {
            for (Client.EncryptedData bobData : bobDataList) {
                compare(aliceData, bobData);
            }
        }

        if (anyMatchFound) {
            System.out.println("At least one of Alice's files contains the same information as one of Bob's files.");
        } else {
            System.out.println("None of Alice's files contain the same information as any of Bob's files.");
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
            IvParameterSpec ivParameterSpec = data.getIvParameterSpec();
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
                Object object;

                while ((object = ois.readObject()) != null) {
                    if (object instanceof Client.EncryptedData) {
                        Client.EncryptedData data = (Client.EncryptedData) object;
                        receiveDataFromClient(clientId, data);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                latch.countDown();
            }
        }
    }
}
