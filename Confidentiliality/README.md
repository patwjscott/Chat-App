# Changes from base version
- Added new headers for base64 encoding, cryptography, and JSON
- added key generation
- Added Encrypt and decrypt functions
- changed message format from plain string to JSON to facilitate using different parts of message easily
- Encrpyted just the message portion as demonstration

# [How to Make a Chat Application in Python](https://www.thepythoncode.com/article/make-a-chat-room-application-in-python)
To run this:
- `pip3 install -r requirements.txt`
- Run `server.py` first to initialize the server.
- Run one or more `client.py` instances and chat!

- If you want to run `client.py` from another machine, make sure you change `SERVER_HOST` in `client.py` to the server's IP address.
