import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.util.Scanner;
import java.util.*;
import java.net.Socket;
public class testModule {
    public static void main(String[] args) {

        try {
            ServerSocket mySocket = new ServerSocket(8080);
            System.out.println("Server started");
            System.out.println("Waiting for client");
            //define the socket
            Socket socket = mySocket.accept();
            //define the writer and reader
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
            //check to see if a client is connected
            if(socket.isConnected()) {
                System.out.println("Client is connected");
                out.write("Connected to server");
            } else {
                System.out.println("Client not found");
            }


        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
