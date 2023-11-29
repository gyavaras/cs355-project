# cs355-project
Zikas Fall CS35500 - Introduction to Cryptography 
Semester Project 
Authors: John Fumo, Brennan Horn, and Genna Yavaraski

Semester Project Description
Alice and Bob are subcontractors of the same company that claims it has given them different code-segments to audit. 
They each receive 5 segments of code, each of which are approximately 500 MB. They want to see if they have received the
same segment, but they do not trust each other to show their segments. 

The goal of this project is to implement a protocol which will allow them to compare Alice and Bob's segments of code 
without any of the parties revealing to the other party the contents of any files. 

Our project contains a Final_Project and Test_Module that each contribute unique functions to the overall solution of 
the problem.

Within the Final_Project module, the following classes (with the respective purpose and usage) are defined

1. Main.java - this file is used to create and run an instance of the server lass, take in the files from Alice and Bob
which will be stored in separate arrays, and create the two instances of the client in which the information will be 
sent to the server.

2. Client.java - this file is used to encrypt (using AES and CBC) and send the files of Bob and Alice to a third party. 
In this file, two threads (one for Bob and one for Alice) store the encoded version of Alice and Bob's file separately.
Additionally, a HMAC is generated in this class to ensure the information being sent to the server is authentic. Once the 
files and enrypted and a HMAC is generated, the information is then sent to the server for comparison. 

3. Server.java - this file is used to verify, decrypt, and compare the files that are sent through the two threads of the
clients. The server is meant to act as a third party that will determine if the files Bob and Alice have are the 
same without the other party knowing. This file contains methods that will begin the server and connect the clients
(Alice and Bob) in order to obtain the files Alie and Bob send through via the Main class. Additionally, the serveer is 
responsible for the comparison of the files and will determine if any of the files passed in by Alice are the same as
any of the files that are passed in by Bob. 

4. ClientHandler.java - this files serves as a concurrent handler for individual client connections.The class is
responsible for initializing a client socket, allowing it to establish input and output streams for sending and receiving
text-based messages. Within the run method, the class can read input from the client and print them out to the terminal.
The handling of each client occurs independently, allowing the server to concurrently manage multiple clients. 

Within the Test_Module, the following classes (with the respective purpose and usage) are defined
NOTE: This module is strictly used for testing purposes.

1. GenerateLargeFile.java - this file is used to generate 500 MB files that can be used as the files Alice and Bob are given.
By changing the name of the file (on line 7), one can produce any number of 500 MB files to be used to test the security
of the server.

2. SecureComparison.java

To run the GenerateLargeFile class, follow the steps below:
1. Go to the class and update the name of the file you wish to create (we used "largeTextFile#.java" where # was replaced with 1-10)
2. Open a terminal in your IDE, and compile the GenerateLargeFile class using: javac GenerateLargeFile.java
   1. If it does not work the first time, make sure you cd into the Test_Module\src folder
3. In the terminal run the GenerateLargeFile class using: java GenerateLargeFile 
   1. If it does not work the first time, make sure you cd into the Test_Module\src folder
4. Wait for the terminal to output "File Generated successfully." and the new file should appear in the Test_Module\src
folder under your project view