import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Main {

        public static void main(String[] args) throws IOException {
            Scanner scanner = new Scanner(System.in);

            byte[] encryptionKey = "1234567890123456".getBytes();
            byte[] macKey = "macKey1234567890".getBytes();

            // Start the server in a separate thread
            Server server = new Server(encryptionKey, macKey, 2); // Assuming 2 clients (Alice and Bob)
            Thread serverThread = new Thread(server::startServer);
            serverThread.start();

            List<String> aliceFilePaths = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                System.out.print("Enter one of Alice's file paths: ");
                aliceFilePaths.add(scanner.nextLine());
            }

            List<String> bobFilePaths = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                System.out.print("Enter one of Bob's file paths: ");
                bobFilePaths.add(scanner.nextLine());
            }

            // Start client threads after collecting all file paths
            Client alice = new Client("Alice", aliceFilePaths, encryptionKey, macKey);
            Thread aliceThread = new Thread(alice);
            aliceThread.start();

            Client bob = new Client("Bob", bobFilePaths, encryptionKey, macKey);
            Thread bobThread = new Thread(bob);
            bobThread.start();
        }


}
