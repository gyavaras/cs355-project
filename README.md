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
We intend to use CBC-Mac with Diffie Hellman to solve this problem. 

One server, one client, and one main class
- the server is responsible for verifying, decrypting, and comparing the files sent in
- the client is responsible for encryption of the files sent in by both parties
- the main is responsible for starting the server, and create two client instances to store Bob and Alice's information separately 
