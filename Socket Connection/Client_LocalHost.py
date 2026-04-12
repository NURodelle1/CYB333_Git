import socket
import sys

# Server address and port (must match the server's HOST and PORT)
SERVER_HOST = '127.0.0.1'  # connecting to local server on this machine
SERVER_PORT = 5000         # port number where the server is expected

# For debugging, print the details of the connection attempt
print("Attempting connection to server at {}:{}...".format(SERVER_HOST, SERVER_PORT))

# Create a TCP/IP socket for the client
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket = clientSocket  # alias for style inconsistency (student-like code)

# Try to connect to the server
try:
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    print("Connected to server at {}:{}".format(SERVER_HOST, SERVER_PORT))
except ConnectionRefusedError:
    # This happens if the server isn't running or is not listening on the specified host/port
    print("Connection failed: Could not reach server at {}:{} (Is it running?)".format(SERVER_HOST, SERVER_PORT))
    sys.exit(1)
except Exception as e:
    # Any other exceptions during connection
    print("Error connecting to server:", e)
    sys.exit(1)

print("Type messages to send to the server. Type 'exit' to disconnect.")

# Communication loop: send messages and receive responses
while True:
    msg = input("You: ")  # Read user input
    if msg == "":
        # If nothing is typed (just pressed Enter), ask for input again
        print("No message entered. Please type something or 'exit' to quit.")
        continue

    # Send the message to the server
    try:
        clientSocket.send(msg.encode('utf-8'))
        print("Message Sent:", msg)  # Debug statement confirming send
    except Exception as e:
        print("Error sending message to server:", e)
        break

    if msg.lower() == "exit":
        # If the user wants to exit, attempt to receive a goodbye from the server and then break
        print("Exit command sent. Waiting for server to close the connection...")
        try:
            data = clientSocket.recv(1024)
            if data:
                print("Server:", data.decode('utf-8'))  # Print the goodbye message from server
        except Exception as e:
            print("Server might have closed the connection without a goodbye. ({})".format(e))
        break

    # Receive response from server (since we didn't exit)
    try:
        data = clientSocket.recv(1024)
    except Exception as e:
        print("Error receiving data from server:", e)
        break

    if not data:
        # If we got an empty response, the server closed the connection unexpectedly
        print("Server closed the connection.")
        break

    reply = data.decode('utf-8')
    print("Server:", reply)

# Clean up the socket
clientSocket.close()
print("Disconnected from the server.")