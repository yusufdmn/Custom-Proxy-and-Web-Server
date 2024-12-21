import socket
import threading

# Constants
PROXY_PORT = 8888
WEB_SERVER_HOST = "localhost"
WEB_SERVER_PORT = 8080
MAX_URI_SIZE = 9999


def handle_client(client_connection, client_address):
    """Handles an individual client connection."""

    try:
        request = client_connection.recv(1024).decode()
        if not request:
            return

        print(f"\nREQUEST FROM {client_address}:\n{request}")

        # Parse the request line
        lines = request.splitlines()
        request_line = lines[0]

        try:
            method, uri, version = request_line.split()
        except ValueError:
            send_error_response(client_connection, 400, "Bad Request")
            return


        # Parse the URI

        if method == "CONNECT":
            send_error_response(client_connection, 405, "HTTPS Not Supported")
            return

        if uri.startswith("http://"):
            uri_parts = uri.split("/", 3)
            if len(uri_parts) < 4:
                path = "/"
            else:
                path = "/" + uri_parts[3]
        else:
            path = uri
        # Validate URI length
        try:
            size = int(path.lstrip("/"))
            if size > MAX_URI_SIZE:
                send_error_response(client_connection, 414, "Request-URI Too Long")
                return
        except ValueError:
            pass  # Not a numeric URI; proceed to forward it

        # Forward the request to the web server
        forward_request_to_server(client_connection, method, path, version, lines[1:])

    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        client_connection.close()




def forward_request_to_server(client_connection, method, path, version, headers):
    """Forwards the request to the appropriate web server based on the Host header."""
    try:
        # Extract the Host from headers
        target_host, target_port = extract_host_and_port(headers)

        # Create a socket to connect to the target web server
        with socket.create_connection((target_host, target_port)) as server_conn:
            # Prepare the request for the web server
            print("Proxy- WebServer connection port: ", server_conn.getsockname()[1])
            request_line = f"{method} {path} {version}\r\n"
            headers_with_host = "\r\n".join(headers) + "\r\n\r\n"
            header_proxy = f"X-Forwarded-By: Proxy Server: 127.0.0.1 {PROXY_PORT}\r\n"
            server_request = request_line + header_proxy + headers_with_host

            print(f"\nForwarding request to server: {target_host}:{target_port}")
            server_conn.sendall(server_request.encode())

            # Relay the response back to the client
            while True:
                data = server_conn.recv(1024)
                if not data:
                    break
                print(f"\nResponse from server:\n{data.decode(errors='ignore')}")  # Log the response
                print(f"Forwarding response to client...")  # Log the response
                client_connection.sendall(data)
    except ConnectionRefusedError:
        send_error_response(client_connection, 404, "Not Found")
    except Exception as e:
        print(f"Error forwarding request to server: {e}")
        send_error_response(client_connection, 500, "Internal Server Error")




def extract_host_and_port(headers):
    """Extracts the host and port from the Host header."""
    for header in headers:
        if header.lower().startswith("host:"):
            host_line = header.split(":", 1)[1].strip()
            if ":" in host_line:
                host, port = host_line.split(":")
                return host, int(port)
            else:
                return host_line, 80  # Default to port 80 if none specified
    raise ValueError("No Host header found in request")


def send_error_response(client_conn, status_code, status_message):
    """Sends an error response to the client."""
    response = f"HTTP/1.1 {status_code} {status_message}\r\n\r\n"
    client_conn.sendall(response.encode())
    print(f"Sent error response: {status_code} {status_message}")


def start_proxy_server():
    """Starts the proxy server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_socket:
        proxy_socket.bind(("127.0.0.1", PROXY_PORT))
        proxy_socket.listen(10)
        print(f"Proxy server listening on port {PROXY_PORT}...")

        while True:
            client_conn, client_addr = proxy_socket.accept()
            thread = threading.Thread(target=handle_client, args=(client_conn, client_addr))
            thread.start()


if __name__ == "__main__":
    try:
        start_proxy_server()
    except KeyboardInterrupt:
        print("\nProxy server shutting down.")
    except Exception as e:
        print(f"Error starting proxy server: {e}")
