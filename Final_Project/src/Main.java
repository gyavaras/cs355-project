import java.util.Scanner;
public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            // Ensure the key length is valid for AES (16 bytes for AES-128)
            byte[] encryptionKey = "1234567890123456".getBytes(); // 16-byte key
            byte[] macKey = "macKey1234567890".getBytes(); // Also 16-byte key

            Server server = new Server(encryptionKey, macKey, 2);

            // Asking Alice to enter her file path
            System.out.print("Enter Alice's file path: ");
            String aliceFilePath = scanner.nextLine();

            // Asking Bob to enter his file path
            System.out.print("Enter Bob's file path: ");
            String bobFilePath = scanner.nextLine();

            Client alice = new Client(server, "Alice", aliceFilePath, encryptionKey, macKey);
            Client bob = new Client(server, "Bob", bobFilePath, encryptionKey, macKey);

            Thread aliceThread = new Thread(alice);
            Thread bobThread = new Thread(bob);

            aliceThread.start();
            bobThread.start();

            server.startComparison();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}