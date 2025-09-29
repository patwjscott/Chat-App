# Authentication
In our Authentication setup, we allow users to register and simply accept they are who they say they are, registering their RSA Public key with the server.
when they then log in, the server accepts the connection, passes the requested public key to them from the list of stored public keys, and sends their stored public key to the peer requested


## User Registration
- Username
- generate Private Key for each new user
- send public key to server for distribution

## Connection Initiation
- Authenticate existing public key - **User Authentication**
- request peers Stored public key from server
- 
- 

## End to End Encrypted Messaging
- Message entered
- generate ecdh key pair
- send _**RSA signed ECDH public key**_ encrypted with peers RSA public key to peer via server
- receive peers **_RSA Signed ecdh public key_**
- decrypt using RSA Private Key and verify signature with peers public key
- derive key
- AESencrypt message using derived key
- send encrypted message to server for redistribution


