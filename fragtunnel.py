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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
        
        # Create tunnel connection
        tunnel_client_socket = tunnel_client()
        if tunnel_client_socket is None:
            log("Failed to create tunnel client")
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
            tunnel_client_socket.close()
        local_connection.close()
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

    except Exception as e:
        log(f"Exception in handle_tunnel_client_concurrent: {e}")
        traceback.print_exc()
    finally:
        conn_manager.remove_connection(conn_id)
        if target_socket:
            target_socket.close()
        tunnel_connection.close()
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
    """Enhanced tunnel server with improved concurrency using thread pool"""
    global TUNNEL_SERVER_PORT
    
    tunnel_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tunnel_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    tunnel_server_address = ('0.0.0.0', TUNNEL_SERVER_PORT)
    tunnel_server_socket.bind(tunnel_server_address)
    tunnel_server_socket.listen(MAX_WORKERS)  # Increased backlog
    
    print(f"Concurrent tunnel server listening on port {TUNNEL_SERVER_PORT} (max {MAX_WORKERS} connections)")

    try:
        while True:
            try:
                tunnel_connection, tunnel_client_address = tunnel_server_socket.accept()
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
        tunnel_server_socket.close()
        connection_executor.shutdown(wait=True)

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

def tunnel_client():
    """Create connection to tunnel server with improved connection handling"""
    global TUNNEL_SERVER_PORT, TUNNEL_SERVER_IP, TARGET_IP, TARGET_PORT

    try:
        tunnel_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tunnel_client_socket.settimeout(CONNECTION_TIMEOUT)
        tunnel_server_address = (TUNNEL_SERVER_IP, TUNNEL_SERVER_PORT)
        tunnel_client_socket.connect(tunnel_server_address)
        log("Connected to tunnel server")

        log(f"Sending target set message: {TARGET_IP}:{TARGET_PORT}")
        if ConcurrentFragTunnel.send_target_set_msg(tunnel_client_socket, TARGET_IP, TARGET_PORT):
            # Wait for response with longer timeout
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

        # Set back to normal timeout for data operations
        tunnel_client_socket.settimeout(1.0)
        return tunnel_client_socket
        
    except Exception as e:
        log(f"Failed to connect to tunnel server: {e}")
        return None

def parse_args():
    parser = argparse.ArgumentParser(
        description="Tunnel client/server with optional AES-encrypted traffic",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("-p", "--port", type=int, help="Local port to listen for app", required=False)
    parser.add_argument("-t", "--target", type=str, help="Target IP:port", required=False, default="")
    parser.add_argument("-T", "--tunnelTo", type=str, help="Tunnel server IP:port", required=False, default="")
    parser.add_argument("-b", "--bind", type=str, help="Tunnel server bind IP:port", required=False, default="")
    parser.add_argument("-e", "--encrypt", type=str, help="Encrypt/encode tunnel traffic using this secret", required=False)
    parser.add_argument("--enc-type", choices=["xor", "aes"], default="xor", help="Encryption type to use")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    parser.add_argument("-w", "--workers", type=int, default=50, help="Max concurrent connections")

    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    LOCAL_PORT = args.port
    VERBOSE = args.verbose
    ENCRYPTED_TUNNEL = False
    SECRET_KEY = b""
    MAX_WORKERS = args.workers

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