&nbsp;	Client generates/receives session key

user enters message

&nbsp;	client uses key to encrypt message

&nbsp;	Client creates HMAC of message

&nbsp;	client send encrypted message  and HMAC to server

&nbsp;		server receives message

&nbsp;		***Server logs message received from user***

&nbsp;		Server sends message to all clients

&nbsp;		***Server logs message forwarded to each client***

		***Server Logs any errors***

&nbsp;	client receives message

&nbsp;	client decrypts message using session key

&nbsp;	client displays message

