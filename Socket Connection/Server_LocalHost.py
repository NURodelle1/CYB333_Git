import socket
import sys  # Added to use sys.exit for a clean exit on errors

# Server configuration (make sure client uses the same HOST and PORT)
HOST = '127.0.0.1'   # Using localhost for the server
PORT = 5000          # Port number for the server to listen on

# Optional: display the server's hostname (for debugging/information)
server_host_name = socket.gethostname()
print("Server starting on host name:", server_host_name)
# Note: The server will actually bind to HOST (127.0.0.1), 
# which is usually the same machine. Using gethostname() here is just for info.

# Create a TCP socket (IPv4 address family, TCP type)
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket = serverSocket  # alias (using a different style variable name for demonstration)

# Allow the port to be reused quickly after the program terminates (avoid 'address in use' error)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind the socket to the specified host and port
try:
    server_socket.bind((HOST, PORT))
    print(f"Server bound to {HOST}:{PORT}")
except Exception as e:
    print(f"Error: Could not bind to {HOST}:{PORT} -> {e}")
    sys.exit(1)  # Exit if binding fails (e.g., port is already in use)

# Listen for incoming connections
server_socket.listen(5)  # backlog of 5 (can queue up to 5 connection requests)
print("Server listening on {}:{}".format(HOST, PORT))

# Wait for a client to connect
try:
    conn, addr = server_socket.accept()
    print("Connected by", addr)  # Output the client's address and port on connection
except Exception as e:
    print("Error accepting connection:", e)
    server_socket.close()
    sys.exit(1)

# Start communication loop with the connected client
while True:
    try:
        data = conn.recv(1024)  # Receive data (bytes) from the client
    except Exception as e:
        print("Error receiving data from client:", e)
        break  # Break loop on error

    if not data:
        # An empty result means the client closed the connection
        print("Connection closed by client.")
        break

    message = data.decode('utf-8')  # Decode bytes to string
    print("Received from client:", message)  # Debug: show the message from the client

    # If the client wants to end the chat
    if message.lower() == "exit":
        print("Client requested disconnection. Closing connection.")
        try:
            conn.send("Goodbye!".encode('utf-8'))  # Send a goodbye message before closing
        except Exception as e:
            print("Error sending goodbye message:", e)
        break  # Exit the loop to close the connection

    # Otherwise, echo the message back to the client
    response_msg = "Echo: " + message
    try:
        conn.send(response_msg.encode('utf-8'))
        print("Sent to client:", response_msg)  # Debug: confirm the response sent
    except Exception as e:
        print("Error sending data to client:", e)
        break  # Exit loop on send failure

# Cleanup: close the connection and server socket
conn.close()
server_socket.close()
print("Server has shut down.")
