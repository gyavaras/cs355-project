import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.DigestInputStream;

import java.net.Socket;
import java.io.DataOutputStream;
import java.util.Base64;
public class Client implements Runnable {
    // Constants for encryption and hashing algorithms
    public static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final String HASH_ALGORITHM = "HmacSHA256";
    // Size of Initialization Vector (IV) in bytes
    private static final int IV_SIZE = 16;
    // SecureRandom for generating random IV
    private static final SecureRandom secureRandom = new SecureRandom();

    // Reference to the server
    private final Server server;
    // Unique identifier for the client
    private final String clientId;
    // Code segment to be sent to the server
    private final String codeSegment;
    // Encryption and MAC keys for securing communication
    private final byte[] encryptionKey;
    private final byte[] macKey;
    // Server address and port
    private String serverAddress;
    private int port;

    // Constructor to initialize the client with necessary parameters
    public Client(Server server, String clientId, String filePath, byte[] encryptionKey, byte[] macKey, String serverAddress, int port) {
        this.server = server;
        this.clientId = clientId;
        this.codeSegment = hashFile(filePath);
        this.encryptionKey = encryptionKey;
        this.macKey = macKey;
        this.serverAddress = serverAddress;
        this.port = port;
    }
    // Compute SHA-256 hash of the file
    private String hashFile(String filePath) {
        try (InputStream fis = new BufferedInputStream(new FileInputStream(filePath));
             DigestInputStream dis = new DigestInputStream(fis, MessageDigest.getInstance("SHA-256"))) {

            byte[] buffer = new byte[8192];
            while (dis.read(buffer) != -1); // Read the file and update the hash calculation
            byte[] hash = dis.getMessageDigest().digest();
            return bytesToHex(hash); // Convert hash to hex string
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // Helper method to convert bytes to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }


    // Run method to be executed when the client is started as a thread
    @Override
    public void run() {
        try (Socket socket = new Socket(serverAddress, port);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {

            EncryptedData data = prepareDataForServer();

            // Send IV, encrypted data, and HMAC
            dos.writeUTF(Base64.getEncoder().encodeToString(data.getIv().getIV()));
            dos.writeUTF(Base64.getEncoder().encodeToString(data.getEncryptedData()));
            dos.writeUTF(Base64.getEncoder().encodeToString(data.getHmac()));
            dos.writeUTF(clientId);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    // Getter method for client ID
    public String getClientId() {
        return clientId;
    }

    // Prepare encrypted data for the server
    private EncryptedData prepareDataForServer() throws Exception {
        byte[] hash = hash(codeSegment);
        IvParameterSpec iv = generateIv();
        byte[] encrypted = encrypt(encryptionKey, iv.getIV(), hash);
        byte[] hmac = createHmac(macKey, encrypted);
        return new EncryptedData(encrypted, hmac, iv);
    }

    // Compute SHA-256 hash of a string
    private byte[] hash(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data.getBytes("UTF-8"));
    }

    // Generate a random Initialization Vector (IV)
    private IvParameterSpec generateIv() {
        byte[] iv = new byte[IV_SIZE];
        secureRandom.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // Encrypt data using AES encryption
    private byte[] encrypt(byte[] key, byte[] iv, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(plaintext);
    }

    // Create HMAC for data integrity verification
    private byte[] createHmac(byte[] key, byte[] data) throws Exception {
        Mac hmac = Mac.getInstance(HASH_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, HASH_ALGORITHM);
        hmac.init(secretKeySpec);
        return hmac.doFinal(data);
    }
    // Inner class to represent encrypted data (IV, encrypted data, HMAC)
    public static class EncryptedData {
        private final byte[] encryptedData;
        private final byte[] hmac;
        private final IvParameterSpec iv;
        // Constructor to initialize the encrypted data
        public EncryptedData(byte[] encryptedData, byte[] hmac, IvParameterSpec iv) {
            this.encryptedData = encryptedData;
            this.hmac = hmac;
            this.iv = iv;
        }
        // Getter method for encrypted data
        public byte[] getEncryptedData() {
            return encryptedData;
        }
        // Getter method for HMAC
        public byte[] getHmac() {
            return hmac;
        }
        // Getter method for IV
        public IvParameterSpec getIv() {
            return iv;
        }
    }
}
