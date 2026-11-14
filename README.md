This was a cryptography assignment during my master’s programme which involves confidentiality and attacks on confidentiality between Alice and Bob.
The method used here was Symmetric encryption, AES-256 with Cipher Block Chaining mode and PKCS#7 padding. 
Alice and Bob has a pre-shared key and Alice sends Bob a confidential message. The Python code shows how Alice was able to send this message.
It revealed how changes in Alice IV can lead to the message being manipulated. The attack here is called the CBC bit flipping attack. 
Finally it also shows how Bob can detect if the message has been altered or tampered. 
