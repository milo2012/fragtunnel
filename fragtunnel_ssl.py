import argparse
import queue
import socket
import threading
import time
import sys
import hashlib
import traceback
import os
import concurrent.futures
import asyncio
import ssl
import ipaddress
import signal
import tempfile
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import datetime
from typing import Optional, Dict, Any

use_aes = False
NONCE_SIZE = 12           # Standard nonce size for AES-GCM

BUFFER_SIZE = 8192
FRAGMENT_SIZE = 1024
MAX_WORKERS = 50  # Maximum concurrent connections
CONNECTION_TIMEOUT = 30.0
FRAGMENT_TIMEOUT = 5.0

SECRET_KEY = b""
ENCRYPTED_TUNNEL = False
VERBOSE = False

TARGET_SET = False
TUNNEL_SERVER_IN_BUFFER = queue.Queue()
TUNNEL_SERVER_OUT_BUFFER = queue.Queue()
TUNNEL_SERVER_IP, TUNNEL_SERVER_PORT, TARGET_IP, TARGET_PORT = str(""), int(0), str(""), int(0)
LOCAL_PORT, BIND_IP = int(0), str("")
CLIENT_TO_TARGET_SOCK = None

# Thread pool for handling connections
connection_executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
fragment_executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS * 2)

# Global SSL context and certificate paths
SSL_ENABLED = False
SSL_CERT_PATH = None
SSL_KEY_PATH = None
ssl_context = None

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    print(f"\nReceived signal {signum}, shutting down gracefully...")
    connection_executor.shutdown(wait=False)
    fragment_executor.shutdown(wait=False)
    sys.exit(0)


def generate_self_signed_cert():
    """Generate a self-signed certificate and private key on the fly"""
    global SSL_CERT_PATH, SSL_KEY_PATH
    
    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TunnelServer"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Create temporary files with proper cleanup
        cert_file = tempfile.NamedTemporaryFile(mode='wb', suffix='.crt', delete=False)
        key_file = tempfile.NamedTemporaryFile(mode='wb', suffix='.key', delete=False)
        
        try:
            # Write certificate
            cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
            cert_file.flush()  # Ensure data is written
            cert_file.close()  # Close before storing path
            SSL_CERT_PATH = cert_file.name
            
            # Write private key
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            key_file.flush()  # Ensure data is written
            key_file.close()  # Close before storing path
            SSL_KEY_PATH = key_file.name
            
        except Exception as e:
            # Clean up on error
            if cert_file and not cert_file.closed:
                cert_file.close()
            if key_file and not key_file.closed:
                key_file.close()
            raise e
        
        log("Generated self-signed SSL certificate")
        return True
        
    except Exception as e:
        log(f"Failed to generate SSL certificate: {e}")
        # Clean up any created files
        if SSL_CERT_PATH and os.path.exists(SSL_CERT_PATH):
            try:
                os.unlink(SSL_CERT_PATH)
            except:
                pass
        if SSL_KEY_PATH and os.path.exists(SSL_KEY_PATH):
            try:
                os.unlink(SSL_KEY_PATH)
            except:
                pass
        return False


def create_ssl_context_server():
    """Create SSL context for the tunnel server"""
    global ssl_context, SSL_CERT_PATH, SSL_KEY_PATH
    
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(SSL_CERT_PATH, SSL_KEY_PATH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # For self-signed certs
        log("Created SSL context for server")
        return context
    except Exception as e:
        log(f"Failed to create SSL context for server: {e}")
        return None

def create_ssl_context_client():
    """Create SSL context for the tunnel client"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Skip certificate verification for self-signed
        log("Created SSL context for client")
        return context
    except Exception as e:
        log(f"Failed to create SSL context for client: {e}")
        return None


class ConnectionManager:
    """Manages active connections and provides connection pooling"""
    def __init__(self):
        self.active_connections = {}
        self.connection_lock = threading.RLock()
        self.connection_counter = 0
    
    def add_connection(self, conn_id: str, connection_info: Dict[str, Any]):
        with self.connection_lock:
            self.active_connections[conn_id] = connection_info
            self.connection_counter += 1
            log(f"Added connection {conn_id}. Total active: {len(self.active_connections)}")
    
    def remove_connection(self, conn_id: str):
        with self.connection_lock:
            if conn_id in self.active_connections:
                del self.active_connections[conn_id]
                log(f"Removed connection {conn_id}. Total active: {len(self.active_connections)}")
    
    def get_connection_count(self):
        with self.connection_lock:
            return len(self.active_connections)

# Global connection manager
conn_manager = ConnectionManager()

class ConcurrentFragmentManager:
    """Thread-safe fragment manager with improved concurrency"""
    def __init__(self):
        self.data = b''
        self.fragmented_data = []
        self.total_data_size = 0
        self.fragmented_data_count = 0
        self.fragmented_data_index = 0
        self.lock = threading.RLock()
        self.fragment_futures = []

    def fragment_data(self, data):
        with self.lock:
            self.data = data
            self.total_data_size = len(self.data)
            self.fragmented_data_count = int(self.total_data_size / FRAGMENT_SIZE) + (
                    self.total_data_size % FRAGMENT_SIZE > 0)

            self.fragmented_data = []
            for i in range(self.fragmented_data_count):
                self.fragmented_data.append(self.data[i * FRAGMENT_SIZE:(i + 1) * FRAGMENT_SIZE])

    def append_fragment(self, fragment):
        with self.lock:
            self.fragmented_data.append(fragment)

    def get_next_fragment(self):
        with self.lock:
            if self.fragmented_data_index < self.fragmented_data_count:
                self.fragmented_data_index += 1
                return self.fragmented_data[self.fragmented_data_index - 1]
            else:
                return None

    def get_fragment_count(self):
        with self.lock:
            return self.fragmented_data_count

    def get_current_fragment_count(self):
        with self.lock:
            return len(self.fragmented_data)

    def get_fragment_and_remove(self):
        with self.lock:
            if self.fragmented_data:
                return self.fragmented_data.pop(0)
            return None

    def get_fragmented_data(self):
        with self.lock:
            return self.fragmented_data.copy()

    def get_total_data_size(self):
        with self.lock:
            return self.total_data_size

    def get_data(self):
        with self.lock:
            return b''.join(self.fragmented_data)

    def clear(self):
        with self.lock:
            self.data = b''
            self.fragmented_data = []
            self.total_data_size = 0
            self.fragmented_data_count = 0
            self.fragmented_data_index = 0
            self.fragment_futures = []

class ConcurrentFragTunnel:
    """Enhanced FragTunnel with concurrent operations"""
    SPECIAL_EOD = str("###>EOD<###")
    SPECIAL_ACK = str("###>ACK<###")
    SPECIAL_ERR = str("###>ERR<###")
    DATA = str("DATA")
    TARGET_STRING = str("####>TARGETIP:PORT<####")

    @staticmethod
    def send_raw_data_async(s, data):
        """Asynchronously send data with proper encryption handling"""
        def _send():
            try:
                if ENCRYPTED_TUNNEL:
                    encrypted_data = encrypt_data(data, use_aes=use_aes)
                    s.sendall(encrypted_data)
                else:
                    s.sendall(data)
                return True
            except Exception as e:
                log(f"Error sending raw data: {e}")
                return False
        
        return fragment_executor.submit(_send)

    @staticmethod
    def send_raw_data(s, data):
        """Send data with proper encryption handling"""
        try:
            if ENCRYPTED_TUNNEL:
                encrypted_data = encrypt_data(data, use_aes=use_aes)
                s.sendall(encrypted_data)
            else:
                s.sendall(data)
            return True
        except Exception as e:
            log(f"Error sending raw data: {e}")
            return False

    @staticmethod
    def send_ack(s):
        return ConcurrentFragTunnel.send_raw_data(s, ConcurrentFragTunnel.SPECIAL_ACK.encode())

    @staticmethod
    def send_eod(s):
        return ConcurrentFragTunnel.send_raw_data(s, ConcurrentFragTunnel.SPECIAL_EOD.encode())

    @staticmethod
    def send_err(s):
        return ConcurrentFragTunnel.send_raw_data(s, ConcurrentFragTunnel.SPECIAL_ERR.encode())

    @staticmethod
    def send_target_set_msg(s, target_ip, target_port):
        try:
            set_target_text = ConcurrentFragTunnel.TARGET_STRING + target_ip + ":" + str(target_port)
            return ConcurrentFragTunnel.send_raw_data(s, set_target_text.encode())
        except Exception as e:
            log(f"Error sending target set message: {e}")
            return False

    @staticmethod
    def recv_data_with_timeout(s, timeout=FRAGMENT_TIMEOUT):
        """Receive data with configurable timeout"""
        original_timeout = s.gettimeout()
        data_obj = {"status": None, "raw_data": None}
        
        try:
            s.settimeout(timeout)
            data = s.recv(FRAGMENT_SIZE)
            if not data:
                return data_obj
            
            # Decrypt if needed
            if ENCRYPTED_TUNNEL:
                try:
                    decrypted_data = decrypt_data(data)
                except Exception as e:
                    log(f"Decryption failed: {e}")
                    data_obj["status"] = ConcurrentFragTunnel.DATA
                    data_obj["raw_data"] = data
                    return data_obj
            else:
                decrypted_data = data
            
            # Try to decode as string to check for special messages
            try:
                decoded_str = decrypted_data.decode('utf-8')
                if decoded_str == ConcurrentFragTunnel.SPECIAL_EOD:
                    data_obj["status"] = ConcurrentFragTunnel.SPECIAL_EOD
                elif decoded_str == ConcurrentFragTunnel.SPECIAL_ACK:
                    data_obj["status"] = ConcurrentFragTunnel.SPECIAL_ACK
                elif decoded_str == ConcurrentFragTunnel.SPECIAL_ERR:
                    data_obj["status"] = ConcurrentFragTunnel.SPECIAL_ERR
                elif decoded_str.startswith(ConcurrentFragTunnel.TARGET_STRING):
                    data_obj["status"] = ConcurrentFragTunnel.TARGET_STRING
                    data_obj["raw_data"] = decrypted_data
                else:
                    data_obj["status"] = ConcurrentFragTunnel.DATA
                    data_obj["raw_data"] = decrypted_data
            except UnicodeDecodeError:
                # Not a string message, treat as binary data
                data_obj["status"] = ConcurrentFragTunnel.DATA
                data_obj["raw_data"] = decrypted_data

            return data_obj
            
        except socket.timeout:
            # Timeout is expected in some cases, return empty result
            return data_obj
        except Exception as e:
            log(f"Error receiving data: {e}")
            return data_obj
        finally:
            s.settimeout(original_timeout)

    @staticmethod
    def recv_data(s):
        return ConcurrentFragTunnel.recv_data_with_timeout(s, 1.0)

    @staticmethod
    def join_fragments(fragments_buffer):
        joined_data_list = []
        while not fragments_buffer.empty():
            joined_data_list.append(fragments_buffer.get())
        return b''.join(joined_data_list)

def derive_key(secret):
    """Derive a consistent 32-byte key from the secret using SHA-256."""
    if isinstance(secret, str):
        secret = secret.encode()
    return hashlib.sha256(secret).digest()  # 32-byte key

def encrypt_data(data, use_aes=True):
    key = derive_key(SECRET_KEY)
    
    if VERBOSE:
        print("[DEBUG] Original data (plaintext):", data)

    xor_first = xor_data(data, key)
    
    if use_aes:
        encrypted = encrypt_aes_gcm(xor_first, key)
        if VERBOSE:
            print("[DEBUG] After XOR:", xor_first)
            print("[DEBUG] After AES-GCM encryption:", encrypted)
        return encrypted
    else:
        if VERBOSE:
            print("[DEBUG] XOR-only encryption:", xor_first)
        return xor_first

def decrypt_data(data, use_aes=True):
    key = derive_key(SECRET_KEY)    
    if use_aes:
        if VERBOSE:
            print("[DEBUG] Encrypted data (input):", data)
        decrypted = decrypt_aes_gcm(data, key)
        xor_final = xor_data(decrypted, key)
        if VERBOSE:
            print("[DEBUG] After AES-GCM decryption:", decrypted)
            print("[DEBUG] After XOR (final plaintext):", xor_final)
        return xor_final
    else:
        xor_final = xor_data(data, key)
        if VERBOSE:
            print("[DEBUG] XOR-only decryption:", xor_final)
        return xor_final

def encrypt_aes_gcm(plaintext, key):
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext  # Prepend nonce

def decrypt_aes_gcm(data, key):
    aesgcm = AESGCM(key)
    try:
        nonce = data[:NONCE_SIZE]
        ciphertext = data[NONCE_SIZE:]
        if VERBOSE:
            print("[DEBUG] Nonce:", nonce.hex())
            print("[DEBUG] Ciphertext:", ciphertext.hex())
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        print("[ERROR] AES-GCM decryption failed:", str(e))
        return b""

def xor_data(data, key):
    """XOR byte data with a repeating key."""
    if not key:
        return data
    extended_key = key * (len(data) // len(key)) + key[:len(data) % len(key)]
    return bytes(b1 ^ b2 for b1, b2 in zip(data, extended_key))

def is_connected(sock):
    if sock is None:
        return False
    try:
        sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        return True
    except socket.error:
        return False

def log(message):
    if VERBOSE:
        timestamp = time.strftime('%H:%M:%S')
        thread_id = threading.current_thread().ident
        print(f"[{timestamp}][Thread-{thread_id}] {message}")

def concurrent_tunnel_client_fragmented_data_sender(tunnel_client_socket, data):
    """Concurrent version of fragmented data sender with parallel fragment sending"""
    try:
        outgoing_fd_manager = ConcurrentFragmentManager()
        outgoing_fd_manager.fragment_data(data)
        fragment_count = outgoing_fd_manager.get_fragment_count()
        
        log(f"Sending {fragment_count} fragments concurrently")
        
        # Send fragments with concurrent ACK handling
        for i in range(fragment_count):
            fragment = outgoing_fd_manager.get_next_fragment()
            
            # Send fragment
            if not ConcurrentFragTunnel.send_raw_data(tunnel_client_socket, fragment):
                log(f"Failed to send fragment {i+1}")
                return False
                
            log(f"Sent fragment {i+1}/{fragment_count}")
            
            # Wait for ACK with timeout
            response = ConcurrentFragTunnel.recv_data_with_timeout(tunnel_client_socket, FRAGMENT_TIMEOUT)
            if response["status"] != ConcurrentFragTunnel.SPECIAL_ACK:
                log(f"Warning: Expected ACK but got {response['status']}")

        # Send EOD
        if not ConcurrentFragTunnel.send_eod(tunnel_client_socket):
            log("Failed to send EOD")
            return False
            
        log("Sent EOD")
        
        # Wait for EOD response
        response = ConcurrentFragTunnel.recv_data_with_timeout(tunnel_client_socket, FRAGMENT_TIMEOUT)
        if response["status"] != ConcurrentFragTunnel.SPECIAL_EOD:
            log(f"Warning: Expected EOD response but got {response['status']}")

        outgoing_fd_manager.clear()
        return True
    except Exception as e:
        log(f"Error in concurrent fragmented data sender: {e}")
        traceback.print_exc()
        return False

def handle_local_client_concurrent(local_connection, local_client_address):
    """Enhanced concurrent handler for local client connections"""
    tunnel_client_socket = None
    incoming_fd_manager = ConcurrentFragmentManager()
    conn_id = f"local_{local_client_address[0]}_{local_client_address[1]}_{int(time.time())}"
    
    try:
        log(f"Handling local client {local_client_address} with connection ID {conn_id}")
        
        # Add to connection manager
        conn_manager.add_connection(conn_id, {
            'type': 'local_client',
            'address': local_client_address,
            'start_time': time.time()
        })
        
        # Create tunnel connection with retry logic
        max_retries = 3
        for attempt in range(max_retries):
            tunnel_client_socket = tunnel_client()
            if tunnel_client_socket is not None:
                break
            if attempt < max_retries - 1:
                log(f"Tunnel connection attempt {attempt + 1} failed, retrying...")
                time.sleep(0.5)
            else:
                log("Failed to create tunnel client after all retries")
                return

        local_connection.settimeout(1.0)
        tunnel_client_socket.settimeout(1.0)

        # Use concurrent futures for handling both directions
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            local_to_tunnel_future = executor.submit(
                handle_local_to_tunnel_flow, 
                local_connection, tunnel_client_socket, conn_id
            )
            tunnel_to_local_future = executor.submit(
                handle_tunnel_to_local_flow, 
                tunnel_client_socket, local_connection, incoming_fd_manager, conn_id
            )
            
            # Wait for either direction to complete/fail
            try:
                concurrent.futures.wait(
                    [local_to_tunnel_future, tunnel_to_local_future],
                    timeout=CONNECTION_TIMEOUT,
                    return_when=concurrent.futures.FIRST_COMPLETED
                )
            except Exception as e:
                log(f"Error in concurrent data flow handling: {e}")
            finally:
                # Cancel any remaining futures
                local_to_tunnel_future.cancel()
                tunnel_to_local_future.cancel()

    except Exception as e:
        log(f"Exception in handle_local_client_concurrent: {e}")
        traceback.print_exc()
    finally:
        conn_manager.remove_connection(conn_id)
        # Use safe cleanup
        safe_socket_close(tunnel_client_socket)
        safe_socket_close(local_connection)
        log(f"Closed connection for {local_client_address}")


def handle_local_to_tunnel_flow(local_connection, tunnel_client_socket, conn_id):
    """Handle data flow from local client to tunnel"""
    try:
        while True:
            try:
                local_data = local_connection.recv(BUFFER_SIZE)
                if not local_data:
                    log(f"[{conn_id}] Local client disconnected")
                    break
                
                log(f"[{conn_id}] Received {len(local_data)} bytes from local client")
                
                # Send to tunnel concurrently
                if not concurrent_tunnel_client_fragmented_data_sender(tunnel_client_socket, local_data):
                    log(f"[{conn_id}] Failed to send data through tunnel")
                    break
                    
            except socket.timeout:
                continue  # No data available, continue
            except Exception as e:
                log(f"[{conn_id}] Error in local to tunnel flow: {e}")
                break
    except Exception as e:
        log(f"[{conn_id}] Exception in handle_local_to_tunnel_flow: {e}")

def handle_tunnel_to_local_flow(tunnel_client_socket, local_connection, incoming_fd_manager, conn_id):
    """Handle data flow from tunnel to local client"""
    try:
        while True:
            try:
                tunnel_data = ConcurrentFragTunnel.recv_data(tunnel_client_socket)
                if tunnel_data["status"] is None:
                    continue
                elif tunnel_data["status"] == ConcurrentFragTunnel.SPECIAL_EOD:
                    # Join fragments and send to local client
                    joined_data = incoming_fd_manager.get_data()
                    if joined_data:
                        local_connection.sendall(joined_data)
                        log(f"[{conn_id}] Sent {len(joined_data)} bytes to local client")
                    incoming_fd_manager.clear()
                    ConcurrentFragTunnel.send_eod(tunnel_client_socket)
                    
                elif tunnel_data["status"] == ConcurrentFragTunnel.DATA:
                    incoming_fd_manager.append_fragment(tunnel_data["raw_data"])
                    ConcurrentFragTunnel.send_ack(tunnel_client_socket)
                    
            except socket.timeout:
                continue  # No data available, continue
            except Exception as e:
                log(f"[{conn_id}] Error in tunnel to local flow: {e}")
                break
    except Exception as e:
        log(f"[{conn_id}] Exception in handle_tunnel_to_local_flow: {e}")

def concurrent_local_server():
    """Enhanced local server with improved concurrency using thread pool"""
    local_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_address = ('127.0.0.1', LOCAL_PORT)
    local_server_socket.bind(server_address)
    local_server_socket.listen(MAX_WORKERS)  # Increased backlog
    
    print(f"Concurrent local server listening on port {LOCAL_PORT} (max {MAX_WORKERS} connections)")

    try:
        while True:
            try:
                local_connection, local_client_address = local_server_socket.accept()
                log(f"New local connection from {local_client_address}")

                # Submit to thread pool instead of creating individual threads
                connection_executor.submit(
                    handle_local_client_concurrent, 
                    local_connection, 
                    local_client_address
                )
                
                log(f"Active connections: {conn_manager.get_connection_count()}")
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                log(f"Error accepting connection: {e}")
                
    except KeyboardInterrupt:
        print("Local server terminated by user")
    finally:
        local_server_socket.close()
        connection_executor.shutdown(wait=True)

def local_client():
    """Create connection to target server with improved error handling"""
    global TARGET_PORT, TARGET_IP
    try:
        local_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_client_socket.settimeout(CONNECTION_TIMEOUT)
        server_address = (TARGET_IP, TARGET_PORT)
        local_client_socket.connect(server_address)
        log("Connected to target server")
        return local_client_socket
    except Exception as e:
        log(f"Failed to connect to target server: {e}")
        return None

def handle_tunnel_client_concurrent(tunnel_connection, tunnel_client_address):
    """Enhanced concurrent handler for tunnel client connections"""
    target_socket = None
    conn_id = f"tunnel_{tunnel_client_address[0]}_{tunnel_client_address[1]}_{int(time.time())}"
    
    log(f"Handling tunnel client {tunnel_client_address} with connection ID {conn_id}")
    
    try:
        # Add to connection manager
        conn_manager.add_connection(conn_id, {
            'type': 'tunnel_client',
            'address': tunnel_client_address,
            'start_time': time.time()
        })
        
        # Create connection to target
        target_socket = local_client()
        if target_socket is None:
            log(f"[{conn_id}] Failed to connect to target server")
            return
                
        target_socket.settimeout(1.0)
        tunnel_connection.settimeout(1.0)
        
        incoming_fd_manager = ConcurrentFragmentManager()

        # Use concurrent futures for bidirectional data flow
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            target_to_tunnel_future = executor.submit(
                handle_target_to_tunnel_flow,
                target_socket, tunnel_connection, conn_id
            )
            tunnel_to_target_future = executor.submit(
                handle_tunnel_to_target_flow,
                tunnel_connection, target_socket, incoming_fd_manager, conn_id
            )
            
            # Wait for either direction to complete/fail
            try:
                concurrent.futures.wait(
                    [target_to_tunnel_future, tunnel_to_target_future],
                    timeout=CONNECTION_TIMEOUT,
                    return_when=concurrent.futures.FIRST_COMPLETED
                )
            except Exception as e:
                log(f"[{conn_id}] Error in concurrent data flow handling: {e}")
            finally:
                # Cancel any remaining futures
                target_to_tunnel_future.cancel()
                tunnel_to_target_future.cancel()

    except Exception as e:
        log(f"Exception in handle_tunnel_client_concurrent: {e}")
        traceback.print_exc()
    finally:
        conn_manager.remove_connection(conn_id)
        # Use safe cleanup
        safe_socket_close(target_socket)
        safe_socket_close(tunnel_connection)
        log(f"Closed tunnel connection for {tunnel_client_address}")


def handle_target_to_tunnel_flow(target_socket, tunnel_connection, conn_id):
    """Handle data flow from target server to tunnel"""
    try:
        while True:
            try:
                local_data = target_socket.recv(BUFFER_SIZE)
                if not local_data:
                    log(f"[{conn_id}] Target server disconnected")
                    break
                    
                log(f"[{conn_id}] Received {len(local_data)} bytes from target server")
                
                # Fragment and send to tunnel client concurrently
                outgoing_fd_manager = ConcurrentFragmentManager()
                outgoing_fd_manager.fragment_data(local_data)
                
                for i in range(outgoing_fd_manager.get_fragment_count()):
                    fragment = outgoing_fd_manager.get_next_fragment()
                    
                    if not ConcurrentFragTunnel.send_raw_data(tunnel_connection, fragment):
                        log(f"[{conn_id}] Failed to send fragment {i+1} to tunnel client")
                        break
                    
                    # Wait for ACK
                    response = ConcurrentFragTunnel.recv_data_with_timeout(tunnel_connection, FRAGMENT_TIMEOUT)
                    if response["status"] != ConcurrentFragTunnel.SPECIAL_ACK:
                        log(f"[{conn_id}] Warning: Expected ACK from tunnel client, got {response['status']}")
                
                # Send EOD
                if not ConcurrentFragTunnel.send_eod(tunnel_connection):
                    log(f"[{conn_id}] Failed to send EOD to tunnel client")
                    break
                
                # Wait for EOD response
                response = ConcurrentFragTunnel.recv_data_with_timeout(tunnel_connection, FRAGMENT_TIMEOUT)
                if response["status"] != ConcurrentFragTunnel.SPECIAL_EOD:
                    log(f"[{conn_id}] Warning: Expected EOD response from tunnel client, got {response['status']}")
                
            except socket.timeout:
                continue  # No data available
            except Exception as e:
                log(f"[{conn_id}] Error in target to tunnel flow: {e}")
                break
    except Exception as e:
        log(f"[{conn_id}] Exception in handle_target_to_tunnel_flow: {e}")

def handle_tunnel_to_target_flow(tunnel_connection, target_socket, incoming_fd_manager, conn_id):
    """Handle data flow from tunnel to target server"""
    try:
        while True:
            try:
                tunnel_data = ConcurrentFragTunnel.recv_data(tunnel_connection)
                if tunnel_data["status"] is None:
                    continue
                elif tunnel_data["status"] == ConcurrentFragTunnel.SPECIAL_EOD:
                    # Join fragments and send to target
                    joined_data = incoming_fd_manager.get_data()
                    if joined_data:
                        target_socket.sendall(joined_data)
                        log(f"[{conn_id}] Sent {len(joined_data)} bytes to target server")
                    incoming_fd_manager.clear()
                    ConcurrentFragTunnel.send_eod(tunnel_connection)
                    
                elif tunnel_data["status"] == ConcurrentFragTunnel.DATA:
                    incoming_fd_manager.append_fragment(tunnel_data["raw_data"])
                    ConcurrentFragTunnel.send_ack(tunnel_connection)
                    
            except socket.timeout:
                continue  # No data available
            except Exception as e:
                log(f"[{conn_id}] Error in tunnel to target flow: {e}")
                break
    except Exception as e:
        log(f"[{conn_id}] Exception in handle_tunnel_to_target_flow: {e}")

def tunnel_set_target(tunnel_connection, tunnel_data=None):
    """Handle target setting process with improved error handling"""
    global TARGET_SET, TARGET_IP, TARGET_PORT

    if tunnel_data is None:
        tunnel_data = ConcurrentFragTunnel.recv_data_with_timeout(tunnel_connection, 10.0)

    if tunnel_data["status"] == ConcurrentFragTunnel.TARGET_STRING:
        try:
            message = tunnel_data["raw_data"].decode()
            log("Setting the target")

            target_str = message[23:]  # Remove TARGET_STRING prefix
            log(f"Received target string: '{target_str}'")
            
            # Split only on the first colon to handle IPv6 addresses
            if ':' not in target_str:
                log("Error: Invalid target format, missing port")
                ConcurrentFragTunnel.send_err(tunnel_connection)
                return False
                
            parts = target_str.split(':', 1)
            target_ip = parts[0]
            
            try:
                target_port = int(parts[1])
            except ValueError:
                log(f"Error: Invalid port number '{parts[1]}'")
                ConcurrentFragTunnel.send_err(tunnel_connection)
                return False
            
            log(f"Parsed target: {target_ip}:{target_port}")
            
            # Test connection to target with timeout
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(5.0)
            try:
                test_socket.connect((target_ip, target_port))
                test_socket.close()
                log("Target connection test successful")
            except Exception as e:
                log(f"Failed to connect to target {target_ip}:{target_port}: {e}")
                ConcurrentFragTunnel.send_err(tunnel_connection)
                return False
            
            # Store target info for this connection (not globally)
            TARGET_IP = target_ip
            TARGET_PORT = target_port
            TARGET_SET = True
            log("Target set successfully")
            ConcurrentFragTunnel.send_ack(tunnel_connection)
            return True
            
        except Exception as e:
            log(f"Error parsing target setting message: {e}")
            ConcurrentFragTunnel.send_err(tunnel_connection)
            return False
    else:
        log(f"Error: Unexpected data received during target setting. Status: {tunnel_data['status']}")
        if tunnel_data['raw_data']:
            log(f"Raw data received: {tunnel_data['raw_data'][:100]}...")
        ConcurrentFragTunnel.send_err(tunnel_connection)
        return False

def concurrent_tunnel_server():
    """Enhanced tunnel server with SSL support"""
    global TUNNEL_SERVER_PORT, SSL_ENABLED
    
    tunnel_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tunnel_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    tunnel_server_address = ('0.0.0.0', TUNNEL_SERVER_PORT)
    tunnel_server_socket.bind(tunnel_server_address)
    tunnel_server_socket.listen(MAX_WORKERS)
    
    ssl_context = None
    
    # Setup SSL if enabled
    if SSL_ENABLED:
        if not generate_self_signed_cert():
            print("Failed to generate SSL certificate, exiting")
            return
        ssl_context = create_ssl_context_server()
        if not ssl_context:
            print("Failed to create SSL context, exiting")
            return
        print(f"Concurrent SSL tunnel server listening on port {TUNNEL_SERVER_PORT} (max {MAX_WORKERS} connections)")
    else:
        print(f"Concurrent tunnel server listening on port {TUNNEL_SERVER_PORT} (max {MAX_WORKERS} connections)")

    try:
        while True:
            try:
                raw_connection, tunnel_client_address = tunnel_server_socket.accept()
                
                # Wrap with SSL if enabled
                if SSL_ENABLED and ssl_context:
                    try:
                        tunnel_connection = ssl_context.wrap_socket(raw_connection, server_side=True)
                        log(f"New SSL tunnel client connection from {tunnel_client_address}")
                    except Exception as e:
                        log(f"SSL handshake failed with {tunnel_client_address}: {e}")
                        safe_socket_close(raw_connection)
                        continue
                else:
                    tunnel_connection = raw_connection
                    log(f"New tunnel client connection from {tunnel_client_address}")

                # Handle target setting and connection in thread pool
                connection_executor.submit(
                    handle_tunnel_connection_setup,
                    tunnel_connection,
                    tunnel_client_address
                )
                
                log(f"Active connections: {conn_manager.get_connection_count()}")
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                log(f"Error accepting tunnel connection: {e}")
                traceback.print_exc()
                
    except KeyboardInterrupt:
        print("Tunnel server terminated by user")
    finally:
        safe_socket_close(tunnel_server_socket)
        connection_executor.shutdown(wait=True)
        
        # Cleanup SSL files
        if SSL_ENABLED and SSL_CERT_PATH and SSL_KEY_PATH:
            try:
                os.unlink(SSL_CERT_PATH)
                os.unlink(SSL_KEY_PATH)
                log("Cleaned up SSL certificate files")
            except:
                pass


def handle_tunnel_connection_setup(tunnel_connection, tunnel_client_address):
    """Handle tunnel connection setup and delegate to data handler"""
    try:
        # First, handle target setting
        tunnel_connection.settimeout(10.0)
        if not tunnel_set_target(tunnel_connection):
            log("Failed to set target, closing connection")
            tunnel_connection.close()
            return
            
        log("Target set for this connection, starting concurrent data handler")

        # Handle the connection with improved concurrency
        handle_tunnel_client_concurrent(tunnel_connection, tunnel_client_address)
        
    except Exception as e:
        log(f"Error in tunnel connection setup: {e}")
        traceback.print_exc()
        tunnel_connection.close()

# Add this import at the top with other imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Replace the entire tunnel_client function
def tunnel_client():
    """Create SSL connection to tunnel server with improved connection handling"""
    global TUNNEL_SERVER_PORT, TUNNEL_SERVER_IP, TARGET_IP, TARGET_PORT, SSL_ENABLED

    raw_socket = None
    tunnel_client_socket = None
    
    try:
        # Create base socket
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.settimeout(CONNECTION_TIMEOUT)
        tunnel_server_address = (TUNNEL_SERVER_IP, TUNNEL_SERVER_PORT)
        raw_socket.connect(tunnel_server_address)
        
        # Wrap with SSL if enabled
        if SSL_ENABLED:
            try:
                # Create fresh SSL context for each connection
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                tunnel_client_socket = context.wrap_socket(
                    raw_socket, 
                    server_hostname=TUNNEL_SERVER_IP
                )
                # CRITICAL: Set raw_socket to None to prevent double cleanup
                raw_socket = None
                log("Connected to tunnel server with SSL")
            except Exception as e:
                log(f"SSL handshake failed: {e}")
                # Only close raw_socket if SSL wrapper failed
                if raw_socket:
                    raw_socket.close()
                    raw_socket = None
                return None
        else:
            tunnel_client_socket = raw_socket
            raw_socket = None  # Prevent double cleanup
            log("Connected to tunnel server")

        log(f"Sending target set message: {TARGET_IP}:{TARGET_PORT}")
        if ConcurrentFragTunnel.send_target_set_msg(tunnel_client_socket, TARGET_IP, TARGET_PORT):
            response = ConcurrentFragTunnel.recv_data_with_timeout(tunnel_client_socket, 10.0)
            if response["status"] == ConcurrentFragTunnel.SPECIAL_ACK:
                log("Target server was set successfully")
            elif response["status"] == ConcurrentFragTunnel.SPECIAL_ERR:
                log("Error: Server rejected target setting")
                tunnel_client_socket.close()
                return None
            else:
                log(f"Error: Unexpected response to target setting: {response['status']}")
                tunnel_client_socket.close()
                return None
        else:
            log("Failed to send target set message")
            tunnel_client_socket.close()
            return None

        tunnel_client_socket.settimeout(1.0)
        return tunnel_client_socket
        
    except Exception as e:
        log(f"Failed to connect to tunnel server: {e}")
        # Clean up properly - only close the socket that exists
        if tunnel_client_socket:
            try:
                tunnel_client_socket.close()
            except:
                pass
        elif raw_socket:
            try:
                raw_socket.close()
            except:
                pass
        return None

def safe_socket_close(sock):
    """Safely close a socket with proper error handling"""
    if sock is None:
        return
    try:
        # For SSL sockets, shutdown first
        if isinstance(sock, ssl.SSLSocket):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
        else:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
        sock.close()
    except Exception as e:
        log(f"Error closing socket: {e}")

# Replace the create_ssl_context_client function
def create_ssl_context_client():
    """Create SSL context for the tunnel client - simplified to avoid context reuse issues"""
    try:
        # Don't reuse global context - create fresh each time
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Skip certificate verification for self-signed
        log("Created SSL context for client")
        return context
    except Exception as e:
        log(f"Failed to create SSL context for client: {e}")
        return None

# Replace the handle_local_client_concurrent function to add better error handling
def handle_local_client_concurrent(local_connection, local_client_address):
    """Enhanced concurrent handler for local client connections"""
    tunnel_client_socket = None
    incoming_fd_manager = ConcurrentFragmentManager()
    conn_id = f"local_{local_client_address[0]}_{local_client_address[1]}_{int(time.time())}"
    
    try:
        log(f"Handling local client {local_client_address} with connection ID {conn_id}")
        
        # Add to connection manager
        conn_manager.add_connection(conn_id, {
            'type': 'local_client',
            'address': local_client_address,
            'start_time': time.time()
        })
        
        # Create tunnel connection with retry logic
        max_retries = 3
        for attempt in range(max_retries):
            tunnel_client_socket = tunnel_client()
            if tunnel_client_socket is not None:
                break
            if attempt < max_retries - 1:
                log(f"Tunnel connection attempt {attempt + 1} failed, retrying...")
                time.sleep(0.5)
            else:
                log("Failed to create tunnel client after all retries")
                return

        local_connection.settimeout(1.0)
        tunnel_client_socket.settimeout(1.0)

        # Use concurrent futures for handling both directions
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            # Submit both data flow directions concurrently
            local_to_tunnel_future = executor.submit(
                handle_local_to_tunnel_flow, 
                local_connection, tunnel_client_socket, conn_id
            )
            tunnel_to_local_future = executor.submit(
                handle_tunnel_to_local_flow, 
                tunnel_client_socket, local_connection, incoming_fd_manager, conn_id
            )
            
            # Wait for either direction to complete/fail
            try:
                concurrent.futures.wait(
                    [local_to_tunnel_future, tunnel_to_local_future],
                    timeout=CONNECTION_TIMEOUT,
                    return_when=concurrent.futures.FIRST_COMPLETED
                )
            except Exception as e:
                log(f"Error in concurrent data flow handling: {e}")

    except Exception as e:
        log(f"Exception in handle_local_client_concurrent: {e}")
        traceback.print_exc()
    finally:
        conn_manager.remove_connection(conn_id)
        if tunnel_client_socket:
            try:
                tunnel_client_socket.close()
            except:
                pass
        try:
            local_connection.close()
        except:
            pass
        log(f"Closed connection for {local_client_address}")

def parse_args():
    parser = argparse.ArgumentParser(
        description="Tunnel client/server with optional AES-encrypted traffic and SSL",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("-p", "--port", type=int, help="Local port to listen for app", required=False)
    parser.add_argument("-t", "--target", type=str, help="Target IP:port", required=False, default="")
    parser.add_argument("-T", "--tunnelTo", type=str, help="Tunnel server IP:port", required=False, default="")
    parser.add_argument("-b", "--bind", type=str, help="Tunnel server bind IP:port", required=False, default="")
    parser.add_argument("-e", "--encrypt", type=str, help="Encrypt/encode tunnel traffic using this secret", required=False)
    parser.add_argument("--enc-type", choices=["xor", "aes"], default="xor", help="Encryption type to use")
    parser.add_argument("--ssl", action="store_true", help="Enable SSL/TLS for tunnel connection")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    parser.add_argument("-w", "--workers", type=int, default=50, help="Max concurrent connections")

    return parser.parse_args()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    args = parse_args()

    LOCAL_PORT = args.port
    VERBOSE = args.verbose
    ENCRYPTED_TUNNEL = False
    SECRET_KEY = b""
    MAX_WORKERS = args.workers
    SSL_ENABLED = args.ssl  # New SSL flag

    if args.encrypt:
        ENCRYPTED_TUNNEL = True
        SECRET_KEY = args.encrypt.encode()

    # Thread pool update example if global pools exist
    if 'connection_executor' in globals():
        connection_executor.shutdown(wait=False)
        fragment_executor.shutdown(wait=False)
        connection_executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
        fragment_executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS * 2)
        print(f"Max workers set to {MAX_WORKERS}")

    # Parse target, tunnel, and bind
    try:
        if args.encrypt:
            SECRET_KEY = args.encrypt.encode()
            ENCRYPTED_TUNNEL = True
            ENCRYPTION_TYPE = args.enc_type.lower()
            if ENCRYPTION_TYPE:
                use_aes = True               

        if args.target:
            ip, port = args.target.split(":")
            TARGET_IP = ip or "127.0.0.1"
            TARGET_PORT = int(port)

        if args.tunnelTo:
            ip, port = args.tunnelTo.split(":")
            TUNNEL_SERVER_IP = ip or "127.0.0.1"
            TUNNEL_SERVER_PORT = int(port)

        if args.bind:
            ip, port = args.bind.split(":")
            BIND_IP = ip or "0.0.0.0"
            TUNNEL_SERVER_PORT = int(port)
            if VERBOSE:
                print(f"Bind port is {TUNNEL_SERVER_PORT}")

    except Exception as e:
        print(f"[!] Argument parsing error: {e}")
        sys.exit(1)

    if SSL_ENABLED:
        print("SSL/TLS encryption enabled for tunnel connection")

    print(f"Running with {MAX_WORKERS} maximum concurrent connections")
    print(f"Connection timeout: {CONNECTION_TIMEOUT}s")
    print(f"Fragment timeout: {FRAGMENT_TIMEOUT}s")

    # Tunnel client side
    if len(args.tunnelTo) > 0 and len(args.target) > 0:
        if len(TUNNEL_SERVER_IP) > 0 and TUNNEL_SERVER_PORT > 0 and len(TARGET_IP) > 0 and TARGET_PORT > 0:
            print(f"Starting concurrent local server on port {LOCAL_PORT}")
            print(f"Forwarding to {TARGET_IP}:{TARGET_PORT} via tunnel {TUNNEL_SERVER_IP}:{TUNNEL_SERVER_PORT}")
            concurrent_local_server()

    # Tunnel server side
    elif len(BIND_IP) > 0 and TUNNEL_SERVER_PORT > 0:
        try:
            print(f"Starting concurrent tunnel server on {BIND_IP}:{TUNNEL_SERVER_PORT}")
            concurrent_tunnel_server()
        except KeyboardInterrupt:
            print("Exiting...")
            connection_executor.shutdown(wait=True)
            fragment_executor.shutdown(wait=True)
            sys.exit(0)
    else:
        print("Invalid arguments provided")
        parser.print_help()