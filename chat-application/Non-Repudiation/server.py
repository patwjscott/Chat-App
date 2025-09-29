######################################
# add logging header
######################################
import socket
import logging
import json
from threading import Thread
from datetime import datetime
logger = logging.getLogger(__name__)

# server's IP address
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5002 # port we want to use
separator_token = "<SEP>" # we will use this to separate the client name & message

# initialize list/set of all connected client's sockets
client_sockets = set()
# create a TCP socket
s = socket.socket()
# make the port as reusable port
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# bind the socket to the address we specified
s.bind((SERVER_HOST, SERVER_PORT))
# listen for upcoming connections
s.listen(5)
######################################
# Create logging instance
######################################
logging.basicConfig(filename="app.log", level=logging.INFO)
logging.basicConfig(filename="app_error.log", level=logging.ERROR)
date_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

logger.info(f"Server started:{date_now}\t {SERVER_HOST}:{SERVER_PORT}")

print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")

def listen_for_client(cs):
    """
    This function keep listening for a message from `cs` socket
    Whenever a message is received, broadcast it to all other connected clients
    """
    while True:
        try:
            # keep listening for a message from `cs` socket
            msg = cs.recv(1024).decode()
            obj = json.loads(msg)
        except Exception as e:
            # client no longer connected
            # remove it from the set
            logger.error(e)
            print(f"[!] Error: please restart the server")
            client_sockets.remove(cs)
        else:
            # if we received a message, replace the <SEP> 
            # token with ": " for nice printing
            if msg != "":
                #msg = msg.replace(separator_token, ": ")
                logger.info(f"[*] {date_now} Received from {obj['name']}")
        # iterate over all connected sockets
        for client_socket in client_sockets:
            # and send the message
            if msg != "":
                try:
                    client_socket.send(msg.encode())
                    logger.info(f"[*] Forwarded: {date_now}\t{client_socket.getpeername()}")
                except socket.error:
                    logger.error(f"socket appears closed")
                #this.close()


while True:
    # we keep listening for new connections all the time
    client_socket, client_address = s.accept()
    logger.info(f"[*] Accepted connection from {client_address}")
    print(f"[+] {client_address} connected.")
    # add the new connected client to connected sockets
    client_sockets.add(client_socket)
    # start a new thread that listens for each client's messages
    t = Thread(target=listen_for_client, args=(client_socket,))
    # make the thread daemon so it ends whenever the main thread ends
    t.daemon = True
    # start the thread
    t.start()

# close client sockets
for cs in client_sockets:
    cs.close()
# close server socket
s.close()
