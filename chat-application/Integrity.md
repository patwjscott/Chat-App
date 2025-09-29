&nbsp;	Client generates/receives session key

user enters message

&nbsp;	client uses key to encrypt message

&nbsp;	***Client creates HMAC of message***

&nbsp;	***client send encrypted message  and HMAC to serve***r

&nbsp;		server relays message to all client

&nbsp;	client receives message

&nbsp;	client decrypts message using session key

&nbsp;	***Client Creates hash of message and compares it against received hash to verify integrity***

&nbsp;	client displays message

