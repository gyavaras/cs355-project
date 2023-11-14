public class Main {
    public static void main(String[] args) {
        try {
            byte[] encryptionKey = "encryptionKey1234".getBytes();
            byte[] macKey = "macKey12345678901".getBytes();

            Server server = new Server(encryptionKey, macKey, 2);

            Client alice = new Client(server, "Alice", "Alice's secret code segment", encryptionKey, macKey);
            Client bob = new Client(server, "Bob", "Bob's secret code segment", encryptionKey, macKey);

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
