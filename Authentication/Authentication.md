1. load rsa key
2. generate ecdh key
3. sign ecdh public key 
4. exchange public ecdh key 
5. derive shared key 
6. generate derivative key
7. encrypt message with using aes with derived key as password 
8. send message

1. receive ecdh key
2. generate ecdh key pair
3. sign ecdh public key
4. exchange ecdh public keys
5. derive shared key
6. generate derivative key
7. receive message
8. decrypt message using aes with derivative key as password

## issues:
Issue: trying to get a response from the peer client, it kept failing verification due to echo from server.
resolution: add logic on server to stop messages echoing back to client that sent original message

&nbsp;	***Client tries to load user private \& public keys from file***

&nbsp;	Client generates/receives session key

&nbsp;	Client connects to server

&nbsp;		***server responds with servers public key***

user enters message

&nbsp;	client uses key to encrypt message

&nbsp;	Client creates HMAC of message

&nbsp;	***Client signs HMAC using user private key***

&nbsp;	***Client Encrypts message \& HMAC … using server public key***

&nbsp;	client send encrypted message and HMAC to server

&nbsp;		server receives message

&nbsp;		***Server decrypts message using server private key***

&nbsp;		Server logs message received from user

		***Server decrypts HMAC using users public key (authentication)***

		***serer generates new hmac for message***

&nbsp;		***If new hmac == received decrypted hmac***

		***re-encrypt hmac with server private key***

&nbsp;		Server sends message to all clients

&nbsp;		Server logs message forwarded to each client

&nbsp;	client receives message

&nbsp;	***client decrypts hmac using server public key***

&nbsp;	client generates new hmac

&nbsp;	client compares new hmac with received hmac

&nbsp;	if hmac match

&nbsp;	client decrypts message using session key

&nbsp;	client displays message

