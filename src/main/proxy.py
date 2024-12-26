import socket
import struct
import sys
import threading
import os
import hashlib

# Constants
PROXY_PORT = 8888
CACHE_DIR = "proxy_cache"
MAX_URI_SIZE = 9999

def handle_client(client_connection, client_address):
    try:
        request = client_connection.recv(1024).decode()
        if not request:
            return

        lines = request.splitlines()
        request_line = lines[0]

        try:
            method, uri, version = request_line.split()
        except ValueError:
            send_error_response(client_connection, 400, "Bad Request")
            print(f"Error: {request_line}")
            return

        if method != "GET":
           # send_error_response(client_connection, 405, "HTTPS Not Supported")
            return

        print(f"\nREQUEST FROM {client_address}:\n{request}")

        if uri.startswith("http://"):
            uri_parts = uri.split("/", 3)
            if len(uri_parts) < 4:
                path = "/"
            else:
                path = "/" + uri_parts[3]
        else:
            path = uri

        try:
            size = int(path.lstrip("/"))
            if size > MAX_URI_SIZE:
                send_error_response(client_connection, 414, "Request-URI Too Long")
                return
        except ValueError:
            pass

        # Check if the URI is in the cache
        cache_filename = get_cache_filename(uri)
        cache_path = os.path.join(CACHE_DIR, cache_filename)

        if os.path.exists(cache_path): # Cache HIT
            print(f"Cache HIT for {uri}")
            with open(cache_path, "rb") as f:
                cached_response = f.read()

            content_length = get_content_length(cached_response)
            if content_length % 2 == 1:  # Odd length, return cached document fully
                print(f"Conditional Get for {uri}, Content-Length: {content_length}.  returning CACHED content...")

                client_connection.sendall(cached_response)
                update_cache_order(cache_path)  # Update LRU order
                return
            else:  # Even length, fetch from server
                print(f"Conditional Get for {uri}, fetching NEW CONTENT from server...")

        forward_request_to_server(client_connection, method, path, version, lines[1:], uri)

    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        client_connection.close()


def forward_request_to_server(client_connection, method, path, version, headers, uri):
    try:
        target_host, target_port = extract_host_and_port(headers)

        target_ip = socket.gethostbyname(target_host)

        with socket.create_connection((target_ip, target_port)) as server_conn:
          #  print("Proxy- WebServer connection port: ", server_conn.getsockname()[1])
            server_conn.settimeout(10)  # Set a 10-second timeout

            request_line = f"{method} {path} {version}\r\n"
            headers_with_host = "\r\n".join(headers) + "\r\n\r\n" #Keep the Host header

            server_request = request_line + headers_with_host

            print(f"\nForwarding request to server: {target_host}:{target_port} ({target_ip})") #Log the IP
            server_conn.sendall(server_request.encode())


            response = b""
            while True:
                data = server_conn.recv(4096)
           #     print(f"Received {len(data)} bytes from server...")
                if not data:
                    break
                response += data

            print(f"\nResponse from server:\n{response.decode(errors='ignore')}")
            print(f"Forwarding response to client...")
            client_connection.sendall(response)

            # close server connection
            server_conn.close()
            cache_response(uri, response)

    except socket.gaierror:
        send_error_response(client_connection, 400, "Bad Hostname")
        print("Error: Could not resolve hostname.")
    except ConnectionRefusedError:
        send_error_response(client_connection, 404, "Not Found")
    except socket.timeout: # When the server returns timeout, send the collected data to the client
        print(f"\nResponse from server:\n{response.decode(errors='ignore')}")
        print(f"Forwarding response to client...")
        client_connection.sendall(response)
        cache_response(uri, response)
    except Exception as e:
        print(f"Error forwarding request to server: {e}")
        send_error_response(client_connection, 500, "Internal Server Error")


def extract_host_and_port(headers):
    for header in headers:
        if header.lower().startswith("host:"):
            host_line = header.split(":", 1)[1].strip()
            if ":" in host_line:
                host, port = host_line.split(":")
                return host, int(port)
            else:
                return host_line, 80  # Default to port 80 if not specified
    raise ValueError("No Host header found in request")


def send_error_response(client_conn, status_code, status_message):
    response = f"HTTP/1.1 {status_code} {status_message}\r\n\r\n"
    client_conn.sendall(response.encode())
    print(f"Sent error response: {status_code} {status_message}")


def get_cache_filename(uri):
    return hashlib.md5(uri.encode()).hexdigest()


def cache_response(uri, response):
    os.makedirs(CACHE_DIR, exist_ok=True)

    status_code = get_status_code(response)
    if status_code < 200 or status_code >= 300:  # Do not cache non-success responses
        print(f"Not caching response for {uri} due to status code {status_code}")
        return

    cache_filename = get_cache_filename(uri)
    cache_path = os.path.join(CACHE_DIR, cache_filename)

    current_cache_size = sum(os.path.getsize(os.path.join(CACHE_DIR, f)) for f in os.listdir(CACHE_DIR) if os.path.isfile(os.path.join(CACHE_DIR, f)))

    if current_cache_size + len(response) > CACHE_SIZE:
        evict_lru_files(current_cache_size + len(response) - CACHE_SIZE)

    with open(cache_path, "wb") as f:
        f.write(response)
    print(f"Cached response for {uri} to {cache_path}")


def evict_lru_files(bytes_to_free):
    files = []
    for filename in os.listdir(CACHE_DIR):
        filepath = os.path.join(CACHE_DIR, filename)
        if os.path.isfile(filepath):
            files.append((filepath, os.path.getmtime(filepath)))  # (path, last modified time)

    files.sort(key=lambda x: x[1])  # Sort by last modified time (oldest first)

    freed_bytes = 0
    for filepath, _ in files:
        if freed_bytes >= bytes_to_free:
            break
        freed_bytes += os.path.getsize(filepath)
        os.remove(filepath)
        print(f"Evicted LRU {filepath} to free up space.")


def update_cache_order(cache_path):
    os.utime(cache_path, None)


def get_content_length(response):
    try:
        headers, _ = response.split(b"\r\n\r\n", 1)
        for line in headers.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                return int(line.split(b":", 1)[1].strip())
    except Exception as e:
        print(f"Error parsing Content-Length: {e}")
    return 0


def get_status_code(response):
    try:
        status_line = response.split(b"\r\n", 1)[0]
        return int(status_line.split(b" ")[1])
    except Exception as e:
        print(f"Error parsing status code: {e}")
    return 0


def start_proxy_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_socket:
        proxy_socket.bind(("127.0.0.1", PROXY_PORT))
        proxy_socket.listen(10)
        print(f"Proxy server listening on port {PROXY_PORT}...")

        while True:
            client_conn, client_addr = proxy_socket.accept()
            thread = threading.Thread(target=handle_client, args=(client_conn, client_addr))
            thread.start()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 server.py <cache_size>")
        sys.exit(1)


    try:
        CACHE_SIZE = int(sys.argv[1])
        start_proxy_server()
    except KeyboardInterrupt:
        print("\nProxy server shutting down.")
    except Exception as e:
        print(f"Error starting proxy server: {e}")
