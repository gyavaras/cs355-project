import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.util.Scanner;
import java.util.*;
import java.net.Socket;
public class testClient {
    public static void main(String[] args) throws IOException {
        try {
            Socket socket = new Socket("localhost", 8080);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String line = in.readLine();
            System.out.println("Server: " + line);
            out.write("Knock knock");
            out.flush();

            in.close();
            out.close();
            socket.close();
        } catch (Exception e) {
            return;
        }

    }
}
