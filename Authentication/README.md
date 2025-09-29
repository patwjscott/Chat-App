# Adding Authentication
### **All messages to server should be encrypted using server public key**
1. add functions in client.py
   1. login
      1. open rsa private key
      2. enter username and password
      3. salt, hash password
      4. encrypt password_hash with private key
      5. encrypt with server public key
      6. send to server
      7. receive auth token and store
   2. register user
      1. get username and password
      2. salt, hash password
      3. create RSA key pair
      4. encrypt with server public key
      5. send to server
2. add functions to server.py
   1. register user
      1. decrypt message with server private key
      2. write to users list file
   2. authorise user
      1. read users list file
      2. find user
      3. use users public key to decrypt password_hash
      4. compare stored password_hash with received password hash
      5. return auth token if successful encrypted with users public key
3. add / menu to client.py *to help with program usage*
   1. /register
   2. /login
   3. /help

# [How to Make a Chat Application in Python](https://www.thepythoncode.com/article/make-a-chat-room-application-in-python)
To run this:
- `pip3 install -r requirements.txt`
- Run `server.py` first to initialize the server.
- Run one or more `client.py` instances and chat!
- If you want to run `client.py` from another machine, make sure you change `SERVER_HOST` in `client.py` to the server's IP address.