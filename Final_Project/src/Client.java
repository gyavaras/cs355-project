import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
public class Client implements Runnable {
    public static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final String HASH_ALGORITHM = "HmacSHA256";
    private static final int IV_SIZE = 16;
    private static final SecureRandom secureRandom = new SecureRandom();

    private final Server server;
    private final String clientId;
    private final String codeSegment;
    private final byte[] encryptionKey;
    private final byte[] macKey;
    public Client(Server server, String clientId, String filePath, byte[] encryptionKey, byte[] macKey) {
        this.server = server;
        this.clientId = clientId;
        this.codeSegment = readFile(filePath); // Read file content
        this.encryptionKey = encryptionKey;
        this.macKey = macKey;
    }
    // Helper method to read file content
    private String readFile(String filePath) {
        try {
            return new String(Files.readAllBytes(Paths.get(filePath)));
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public void run() {
        try {
            EncryptedData data = prepareDataForServer();
            server.receiveDataFromClient(this, data);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String getClientId() {
        return clientId;
    }

    private EncryptedData prepareDataForServer() throws Exception {
        byte[] hash = hash(codeSegment);
        IvParameterSpec iv = generateIv();
        byte[] encrypted = encrypt(encryptionKey, iv.getIV(), hash);
        byte[] hmac = createHmac(macKey, encrypted);
        return new EncryptedData(encrypted, hmac, iv);
    }

    private byte[] hash(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data.getBytes("UTF-8"));
    }

    private IvParameterSpec generateIv() {
        byte[] iv = new byte[IV_SIZE];
        secureRandom.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private byte[] encrypt(byte[] key, byte[] iv, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(plaintext);
    }

    private byte[] createHmac(byte[] key, byte[] data) throws Exception {
        Mac hmac = Mac.getInstance(HASH_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, HASH_ALGORITHM);
        hmac.init(secretKeySpec);
        return hmac.doFinal(data);
    }

    public static class EncryptedData {
        private final byte[] encryptedData;
        private final byte[] hmac;
        private final IvParameterSpec iv;

        public EncryptedData(byte[] encryptedData, byte[] hmac, IvParameterSpec iv) {
            this.encryptedData = encryptedData;
            this.hmac = hmac;
            this.iv = iv;
        }

        public byte[] getEncryptedData() {
            return encryptedData;
        }

        public byte[] getHmac() {
            return hmac;
        }

        public IvParameterSpec getIv() {
            return iv;
        }
    }
}
