import java.io.IOException;
import java.io.*;
import java.net.*;

public class Server {
    public static void main(String[] args) {
        //define the server socket
        ServerSocket server = null;
        try {
            //server is now listening on port 8008
            server = new ServerSocket(8008);
            server.setReuseAddress(true);

            //start the infinite loop for client requests
            while(true) {
                //make a client socket to accept incoming clients
                Socket client = server.accept();
                // Displaying that new client is connected to server
                System.out.println("New client connected" + client.getInetAddress().getHostAddress());
                // create a new thread object
                ClientHandler clientSock = new ClientHandler(client);

                // This thread will handle the client
                // separately
                new Thread(clientSock).start();
            }

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (server != null) {
                try {
                    server.close();
                }
                catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
