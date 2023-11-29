import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Main {

        public static void main(String[] args) throws IOException {
            Scanner scanner = new Scanner(System.in);
            byte[] encryptionKey = "1234567890123456".getBytes();
            byte[] macKey = "macKey1234567890".getBytes();
            Server server = new Server(encryptionKey, macKey, 2);
            Thread serverThread = new Thread(server::startServer);
            serverThread.start();
            List<String> aliceFilePaths = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                System.out.print("Enter file #" + (i + 1) +" for Alice: ");
                aliceFilePaths.add(scanner.nextLine());
            }
            List<String> bobFilePaths = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                System.out.print("Enter file #" + (i + 1) +" for Bob: ");
                bobFilePaths.add(scanner.nextLine());
            }
            Client alice = new Client("Alice", aliceFilePaths, encryptionKey, macKey);
            Thread aliceThread = new Thread(alice);
            aliceThread.start();

            Client bob = new Client("Bob", bobFilePaths, encryptionKey, macKey);
            Thread bobThread = new Thread(bob);
            bobThread.start();
        }


}
