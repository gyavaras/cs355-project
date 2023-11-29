import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


import java.io.InputStream;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.DigestInputStream; // If you're using DigestInputStream for hashing


public class Client implements Runnable, Serializable {
    // Constants for encryption and hashing algorithms
    public static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final String HASH_ALGORITHM = "HmacSHA256";
    private static final int IV_SIZE = 16;
    private static final SecureRandom secureRandom = new SecureRandom();
    // Client-specific information
    private final String clientId;
    private final List<String> codeSegmentList = new ArrayList<>();
    private final byte[] encryptionKey;
    private final byte[] macKey;
    private transient Socket socket;
    // Constructor to initialize client with ID, file paths, and keys
    public Client(String clientId, List<String> filePaths, byte[] encryptionKey, byte[] macKey) throws IOException {
        this.clientId = clientId;
        this.encryptionKey = encryptionKey;
        this.macKey = macKey;
        // Hash code segments from the file paths that alice and bob pass through
        for (String filePath : filePaths) {
            this.codeSegmentList.add(hashFile(filePath));
        }
        // Connect to the server using just a local port
        this.socket = new Socket("localhost", 12345);
    }

    // Implementation of the Runnable interface for concurrent execution
    @Override
    public void run() {
        try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())) {
            out.writeObject(clientId); // Send the client ID first
            // Send encrypted data for each code segment to the server
            for (String codeSegment : codeSegmentList) {
                EncryptedData data = prepareDataForServer(codeSegment);
                out.writeObject(data); // Sends the data to server
            }
            out.writeObject(null); // Indicate end of data/file
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            //Same as in server just makes sure the socket it correctly closed
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    // Method to hash the contents of a file using SHA-256
    private String hashFile(String filePath) {
        //opens a input stream so that we can read the file
        try (InputStream fis = new BufferedInputStream(new FileInputStream(filePath));
             //If we wrap the input stream with digest we can compute sha 256 of it
             DigestInputStream dis = new DigestInputStream(fis, MessageDigest.getInstance("SHA-256"))) {
            //holds the data to be read
            byte[] buffer = new byte[8192];
            //reads the file into the buffer until the file is empty
            while (dis.read(buffer) != -1); // Read the file and update the hash calculation
            byte[] hash = dis.getMessageDigest().digest();
            return bytesToHex(hash); // Convert hash to hex string because it is not easily to transmit, also easier to read
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    // Utility method to convert byte array to hexadecimal string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    // Method to prepare encrypted data for transmission to the server
    private EncryptedData prepareDataForServer(String data) throws Exception {
        byte[] hash = hash(data);
        IvParameterSpec iv = generateIv();
        byte[] encrypted = encrypt(encryptionKey, iv.getIV(), hash);
        byte[] hmac = createHmac(macKey, encrypted);
        return new EncryptedData(encrypted, hmac, iv.getIV());  // Pass IV as byte array
    }

    // Method to hash data using SHA-256
    private byte[] hash(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data.getBytes("UTF-8"));
    }
    // Method to generate a random Initialization Vector (IV)
    private IvParameterSpec generateIv() {
        byte[] iv = new byte[IV_SIZE];
        secureRandom.nextBytes(iv);
        return new IvParameterSpec(iv);
    }
    // Method to encrypt data using AES algorithm
    private byte[] encrypt(byte[] key, byte[] iv, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(plaintext);
    }
    // Method to create HMAC (Hash-based Message Authentication Code)
    private byte[] createHmac(byte[] key, byte[] data) throws Exception {
        Mac hmac = Mac.getInstance(HASH_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, HASH_ALGORITHM);
        hmac.init(secretKeySpec);
        return hmac.doFinal(data);
    }
    // Inner class representing encrypted data for transmission
    public static class EncryptedData implements Serializable {
        private final byte[] encryptedData;
        private final byte[] hmac;
        private final byte[] iv;  // Store IV as a byte array
        // Constructor for EncryptedData
        public EncryptedData(byte[] encryptedData, byte[] hmac, byte[] iv) {
            this.encryptedData = encryptedData;
            this.hmac = hmac;
            this.iv = iv;  // Store the IV bytes directly
        }

        // Getters
        public byte[] getEncryptedData() {
            return encryptedData;
        }

        public byte[] getHmac() {
            return hmac;
        }

        public byte[] getIv() {
            return iv;
        }

        // Method to convert byte array back to IvParameterSpec
        public IvParameterSpec getIvParameterSpec() {
            return new IvParameterSpec(iv);
        }
    }


    // Getter for client ID
    public String getClientId() {
        return clientId;
    }
}
