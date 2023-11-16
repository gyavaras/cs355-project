import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            byte[] encryptionKey = "encryptionKey1234".getBytes();
            byte[] macKey = "macKey12345678901".getBytes();

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

