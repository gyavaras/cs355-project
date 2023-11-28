import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Client implements Runnable {
    public static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final String HASH_ALGORITHM = "HmacSHA256";
    private static final int IV_SIZE = 16;
    private static final SecureRandom secureRandom = new SecureRandom();

    private final Server server;
    private final String clientId;
    private final List<String> codeSegmentList = new ArrayList<>();
    private final byte[] encryptionKey;
    private final byte[] macKey;

    public Client(Server server, String clientId, List<String> filePaths, byte[] encryptionKey, byte[] macKey) {
        this.server = server;
        this.clientId = clientId;
        this.encryptionKey = encryptionKey;
        this.macKey = macKey;
        for (String filePath : filePaths) {
            this.codeSegmentList.add(hashFile(filePath));
        }
    }

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

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Override
    public void run() {
        try {
            for (String codeSegment : codeSegmentList) {
                EncryptedData data = prepareDataForServer(codeSegment);
                server.receiveDataFromClient(this, data);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String getClientId() {
        return clientId;
    }

    private EncryptedData prepareDataForServer(String data) throws Exception {
        byte[] hash = hash(data);
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
