public class Main {

        public static void main(String[] args) {
            try {
                byte[] encryptionKey = "encryptionKey1234".getBytes();
                byte[] macKey = "macKey12345678901".getBytes();

                Server server = new Server(encryptionKey, macKey, 2);

                // Replace these file paths with the actual paths of Alice and Bob's files
                String aliceFilePath = "path/to/alice_file.txt";
                String bobFilePath = "path/to/bob_file.txt";

                Client alice = new Client(server, "Alice", aliceFilePath, encryptionKey, macKey);
                Client bob = new Client(server, "Bob", bobFilePath, encryptionKey, macKey);

                Thread aliceThread = new Thread(alice);
                Thread bobThread = new Thread(bob);

                aliceThread.start();
                bobThread.start();

                server.startComparison();

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

