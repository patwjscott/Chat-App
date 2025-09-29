## Sending
1. load rsa key
2. generate ecdh key
3. sign ecdh public key 
4. exchange public ecdh key 
5. derive shared key 
6. generate derivative key
7. encrypt message with using aes with derived key as password 
8. send message

## Receiving
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
