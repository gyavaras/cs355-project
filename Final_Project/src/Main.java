import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            // Ensure the key length is valid for AES (16 bytes for AES-128)
            byte[] encryptionKey = "1234567890123456".getBytes(); // 16-byte key
            byte[] macKey = "macKey1234567890".getBytes(); // Also 16-byte key

            // Since we have 5 files from Alice and 5 from Bob, we set clientCount to 10
            Server server = new Server(encryptionKey, macKey, 10);

            // Collect 5 file paths for Alice
            List<String> aliceFilePaths = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                System.out.print("Enter one of Alice's file paths: ");
                aliceFilePaths.add(scanner.nextLine());
            }

            // Collect 5 file paths for Bob
            List<String> bobFilePaths = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                System.out.print("Enter one of Bob's file paths: ");
                bobFilePaths.add(scanner.nextLine());
            }

            // Create and start threads for Alice's files
            Client alice = new Client(server, "Alice", aliceFilePaths, encryptionKey, macKey);
            Thread aliceThread = new Thread(alice);
            aliceThread.start();

            // Create and start threads for Bob's files
            Client bob = new Client(server, "Bob", bobFilePaths, encryptionKey, macKey);
            Thread bobThread = new Thread(bob);
            bobThread.start();

            // Start the comparison process on the server
            server.startComparison();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}
