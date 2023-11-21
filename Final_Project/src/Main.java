import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            // Key and server details initialization
            byte[] encryptionKey = "1234567890123456".getBytes(); // 16-byte key for AES
            byte[] macKey = "macKey1234567890".getBytes(); // 16-byte key for HMAC
            String serverAddress = "127.0.0.1"; // Localhost (for local testing)
            int serverPort = 12345; // Port number for the server to listen on

            // Start the server in a separate thread
            Server server = new Server(encryptionKey, macKey, 2, serverPort);
            Thread serverThread = new Thread(server::startServer);
            serverThread.start();

            // Give the server some time to start
            try {
                Thread.sleep(1000); // Waiting 1 second for the server to initialize
            } catch (InterruptedException e) {
                System.out.println("Interrupted while waiting for the server to start.");
            }

            // Input file paths for Alice and Bob
            System.out.print("Enter Alice's file path: ");
            String aliceFilePath = scanner.nextLine();

            System.out.print("Enter Bob's file path: ");
            String bobFilePath = scanner.nextLine();

            // Create and start client threads
            Client alice = new Client(server, "Alice", aliceFilePath, encryptionKey, macKey, serverAddress, serverPort);
            Client bob = new Client(server, "Bob", bobFilePath, encryptionKey, macKey, serverAddress, serverPort);

            Thread aliceThread = new Thread(alice);
            Thread bobThread = new Thread(bob);

            aliceThread.start();
            bobThread.start();

            // Wait for both threads to finish
            aliceThread.join();
            bobThread.join();

            // Server will automatically handle the comparison once both clients have connected and sent their data
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}
