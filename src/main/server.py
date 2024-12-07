import socket
import threading

# Constants for the valid range of the document size
MIN_SIZE = 100
MAX_SIZE = 20000

def handle_client(connection, address):
    """Handle an individual client connection."""
    try:
        request = connection.recv(1024).decode()
        print(f"\n\nRECIEVED REQUEST FROM {address}:\n\n{request}")

        # Parse the request
        lines = request.splitlines()
        if not lines:
            send_error_response(connection, 400, "Bad Request")
            return

        # Extract the method, URI, and HTTP version
        try:
            method, uri, version = lines[0].split()
        except ValueError:
            send_error_response(connection, 400, "Bad Request")
            return

        # Validate the method
        if method != "GET":
            send_error_response(connection, 501, "Not Implemented")
            return

        # Parse and validate the URI
        try:
            size = int(uri.lstrip('/'))
            if size < MIN_SIZE or size > MAX_SIZE:
                raise ValueError("Size out of range")
        except ValueError:
            send_error_response(connection, 400, "Bad Request")
            return

        # Generate the HTML document of the specified size
        content = generate_html_content(size)

        # Send the response
        send_response(connection, 200, "OK", content)

    except Exception as e:
        print(f"Error handling request from {address}: {e}")
    finally:
        connection.close()


def send_response(connection, status_code, status_message, content):
    """Send an HTTP response to the client."""
    content_length = len(content)
    response_line = f"HTTP/1.1 {status_code} {status_message}\r\n"
    headers = (
        f"Content-Type: text/html\r\n"
        f"Content-Length: {content_length}\r\n\r\n"
    )
    response = response_line + headers + content
    connection.sendall(response.encode())
    print(f"\nSENT RESPONSE:\n\n{response}\n")


def send_error_response(connection, status_code, status_message):
    """Send an error response to the client."""
    response_line = f"HTTP/1.1 {status_code} {status_message}\r\n\r\n"
    headers = (
        f"{status_code}Error: {status_message}\r\n"
    )
    response = response_line + headers
    connection.sendall(response.encode())
    print(f"SENT ERROR RESPONSE: {response_line.strip()}")


def generate_html_content(size):
    """Generate an HTML document with the specified size."""
    head = f"<HTML>\n<HEAD>\n<TITLE>I am {size} bytes long</TITLE>\n</HEAD>\n"
    init_body = '<BODY> '
    end_tag = '</BODY>\n</HTML>'
    remaining_size = size - len(head) - len(init_body) - len(end_tag)

    # Generate body content
    body = ''.join('a ' for _ in range(remaining_size // 2))

    if remaining_size > len(body):
        body += 'a'

    return head + init_body + body + end_tag

def start_server(port):
    """Start the HTTP server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)
    print(f"Server listening on port {port}...")

    while True:
        client_socket, client_address = server_socket.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        thread.start()


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 server.py <port>")
        sys.exit(1)

    try:
        port = int(sys.argv[1])
        start_server(port)
    except ValueError:
        print("Error: Port must be an integer.")
        sys.exit(1)
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)
