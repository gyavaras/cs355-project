import java.io.FileOutputStream;
import java.io.IOException;

public class GenerateLargeFile {

    public static void main(String[] args) {
        String filePath = "largeFile2.txt";
        long targetSize = 500 * 1024 * 1024; // 500 MB

        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            while (getFilesize(filePath) < targetSize) {
                // Writing 1 MB of random data at a time
                byte[] data = generateRandomData(1024 * 1024);
                fos.write(data);
            }
            System.out.println("File generated successfully.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static byte[] generateRandomData(int size) {
        byte[] data = new byte[size];
        // You can customize this to generate any kind of data you want
        for (int i = 0; i < size; i++) {
            data[i] = (byte) (Math.random() * 256 - 128);
        }
        return data;
    }

    private static long getFilesize(String filePath) {
        return new java.io.File(filePath).length();
    }
}