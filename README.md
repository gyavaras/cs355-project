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

Our Approach
We intend to use CBC-Mac with Diffie Hellman to solve this problem. Our project contains a Final_Project and Test_Module
that each contribute unique functions to the overall solution of the problem.

Within the Final_Project module, the following classes (with the respective purpose and usage) are defined

1. Client.java - this file is used to encrypt and send the files of Bob and Alice to a third party. In this file, two 
threads (one for Bob and one for Alice) are created that each store the encoded version of Alice and Bob's file separately.
Additionally, a MAC is generated in this class to ensure the information being sent to the server is authentic. Once the 
files and enrypted and a MAC is generated, the information is then sent to the server for comparison.

2. Server.java - this file is used to verify, decrypt, and compare the files that are sent through the two threads of the
client server. The server is meant to act as a third party that will determine if the files Bob and Alice have are the 
same without the other party knowing. 

3. Main.java - this file is used to run the server and create the two instances of the client in which the information
will be sent to the server. 

Within the Test_Module, the following classes (with the respective purpose and usage) are defined
NOTE: This module is strictly used for testing purposes.

1. GenerateLargeFile - this file is used to generate 500 MB files that can be used as the files Alice and Bob are given.
By changing the name of the file (on line 7), one can produce any number of 500 MB files to be used to test the security
of the server. 