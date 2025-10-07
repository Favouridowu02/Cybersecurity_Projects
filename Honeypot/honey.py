#!/usr/bin/env python3
"""
    This Module contains Honeypot class for managing honeypot instances.
"""
import datetime, json, socket, threading, time, sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR= BASE_DIR / "logs"


class Honeypot:
    def __init__(self, bind_ip="0.0.0.0", ports=None):
        """
            This is the Initialization of the Class
        """
        self.bind_ip = bind_ip
        self.ports = ports or [21, 22, 80, 443]
        self.active_connections = {}
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.log_file = LOG_DIR / f"honey_pot{datetime.datetime.now().strftime('%Y%m%d')}.json" 

    def log_activity(self, port, remote_ip, data):
        """
            Log suspicious activity with timestamp and details.
        """
        activity = {
            "timestamp": datetime.datetime.now().isoformat(),
            "remote_ip": remote_ip,
            "port": port,
            "data": data.decode("utf-8", errors='ignore'),
        }
        with open(self.log_file, 'a') as f:
            json.dump(activity, f)
            f.write("\n")

    def handle_connection(self, client_socket, remote_ip, port):
        """Handle individual connections and emulate services"""
        service_banners = {
            21: "220 FTP server ready\r\n",
            22: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n",
            80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n",
            443: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n"
        }
        try:
            if port in service_banners:
                client_socket.send(service_banners[port].encode())

            while True:
                data = client_socket.recv(1024)
                if not data:
                    break

                self.log_activity(port, remote_ip, data)

                client_socket.send(b"Command not recognize.\r\n")
        except Exception as e:
            print(f'Error handling connection: {e}')
        finally:
            client_socket.close()

    ## The Network Listener
    def start_listener(self, port):
        """Start a Listener on specified port"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind((self.bind_ip, port))
            server.listen(5)

            print(f"[*] Listening on {self.bind_ip}:{port}")

            while True:
                client, addr = server.accept()
                print(f"[*] Accepted connection from {addr[0]:addr[1]}")

                client_handler = threading.Threading(
                    target=self.handle_connection,
                    args=(client, addr[0], port)
                )
                client_handler.start()

        except Exception as e:
            print(f"Error starting listener on port {port}: {e}")

def main():
    honeypot = Honeypot()

    for port in honeypot.ports:
        listener_thread = threading.Thread(
            target = honeypot.start_listener,
            args = (port,)
        )
        listener_thread.daemon = True
        listener_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down honeypot...")
        sys.exit(0)

if __name__ == "__main__":
    main()      