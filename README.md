# Application of CIANA demonstration
The base code is from https://thepythoncode.com/article/make-a-chat-room-application-in-python

## Goal
to demonstrate the application of CIANA throughout development of an application

## Confidentiality
In this version I implement AES265 to provide encryption, we create a key for the clients to share with each other

## Integrity
Integrity implements HMAC using SHA256 to create a hash with changes with any changes made to the message

## Non-Repudiation
Here I implement logging in the server to stop users from denying the knowledge of messages they have sent or received

## Authentication
In this version of the code I implement RSA keys, Elliptic Curve Diffie-Hellman Ephemeral key exchange. we change the HMAC to SHA256 signatures using the RSA keys and use the ECDHE keys to encrypt the message using AES256
