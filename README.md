# cs355-project
Zikas Fall CS35500 - Introduction to Cryptography 
Semester Project 


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

To run the GenerateLargeFile class, follow the steps below:
1. Go to the class and update the name of the file you wish to create (we used "largeTextFile#.java" where # was replaced with 1-10)
2. Open a terminal in your IDE, and compile the GenerateLargeFile class using: javac GenerateLargeFile.java
   1. If it does not work the first time, make sure you cd into the Test_Module\src folder
3. In the terminal run the GenerateLargeFile class using: java GenerateLargeFile 
   1. If it does not work the first time, make sure you cd into the Test_Module\src folder
4. Wait for the terminal to output "File Generated successfully." and the new file should appear in the Test_Module\src
folder under your project view



Libraries and Packages:
Java.util: Used for Array Lists and Arrays which helped with the file paths from the users
Java.io:  It is used for reading from and writing to data streams which we used for file reading of the client’s files.
java.net: Used for socket programming capabilities to allow the client to send and receive data over our network. 
javax.crypto: Provides the classes and interfaces for cryptographic operations.
java.security: Generation of random numbers and hash digests which we used sha-256.

Security Analysis Summary:
The goal of the project was to create an interface between two clients and a server so that the clients could independently send five 500 mb files to the server without being altered or read by anyone except by the sender and receiver. The client/server system was set up using socket programming and threading so we could have multiple clients running on the server at a time (in this case 2, Alice and Bob). We utilized symmetric-key cryptography and assumed both the clients and the servers already had a key established and known.
After establishing the client/server connections we hashed the files to a more manageable length using SHA-256 hashing that created a fixed sized digest that represents the file’s contents. We then encrypted the hashed file using AES-CBC encryption. The encrypted file was then sent through an HMAC to ensure that the file will not be tampered with should it be intercepted. The server then receives the 10 files (5 from Alice and 5 from Bob), verifies the files, decrypts, and de-hashes the files and then compares the contents of the files. If any of the files from Alice or Bob match, it prints to the console that there was at least one match found. Otherwise it prints that no matches were found.
All of the schemes used (SHA-256, HMAC, and CBC-AES) were implemented using Java libraries.
