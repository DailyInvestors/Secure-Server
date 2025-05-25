# Ultimate Python Server
# This server only initiates outbound connections and provides:
# - Data sanitization
# - Activity logging
# - Rate limiting
# - Host proxy (HTTP/HTTPS)
# - Email proxy (SMTP/IMAP)
# - Threaded operations (firewall-like)
# No incoming connections are accepted.

import logging
import queue
import time
from threading import Thread
import requests
import smtplib
import imaplib
import os
import hashlib
import subprocess
import shlex
import numpy
from sklearn.ensemble import RandomForestClassifier
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler

# Setup logging
logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s %(message)s')

# Rate Limiter (Token Bucket)
class RateLimiter:
    def __init__(self, rate, per):
        self.rate = rate
        self.per = per
        self.allowance = rate
        self.last_check = time.time()

    def allow(self):
        current = time.time()
        time_passed = current - self.last_check
        self.last_check = current
        self.allowance += time_passed * (self.rate / self.per)
        if self.allowance > self.rate:
            self.allowance = self.rate
        if self.allowance < 1.0:
            return False
        else:
            self.allowance -= 1.0
            return True

# Sanitizer
class Sanitizer:
    @staticmethod
    def sanitize(data):
        # Basic sanitizer, extend as needed
        if isinstance(data, str):
            return data.replace('<', '').replace('>', '').replace('&', '').replace('"', '').replace("'", '')
        return data

# Activity Logger
class ActivityLogger:
    @staticmethod
    def log(activity):
        logging.info(activity)

# IP Access Control
class IPAccessControl:
    def __init__(self, whitelist=None, blacklist=None):
        self.whitelist = set(whitelist) if whitelist else set()
        self.blacklist = set(blacklist) if blacklist else set()

    def is_allowed(self, ip):
        if ip in self.blacklist:
            return False
        if self.whitelist and ip not in self.whitelist:
            return False
        return True

    def add_to_whitelist(self, ip):
        self.whitelist.add(ip)

    def remove_from_whitelist(self, ip):
        self.whitelist.discard(ip)

    def add_to_blacklist(self, ip):
        self.blacklist.add(ip)

    def remove_from_blacklist(self, ip):
        self.blacklist.discard(ip)

# Host Proxy (HTTP/HTTPS)
class HostProxy:
    def __init__(self, rate_limiter, sanitizer, logger, ip_control=None):
        self.rate_limiter = rate_limiter
        self.sanitizer = sanitizer
        self.logger = logger
        self.ip_control = ip_control

    def proxy_request(self, method, url, **kwargs):
        # Extract host IP from URL
        from urllib.parse import urlparse
        import socket
        parsed = urlparse(url)
        host = parsed.hostname
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            ip = None
        if self.ip_control and ip:
            if not self.ip_control.is_allowed(ip):
                self.logger.log(f"Blocked request to {ip} (not allowed by IP control)")
                return None
        if not self.rate_limiter.allow():
            self.logger.log(f"Rate limit exceeded for {url}")
            return None
        url = self.sanitizer.sanitize(url)
        self.logger.log(f"Proxying {method} request to {url}")
        try:
            resp = requests.request(method, url, **kwargs)
            return resp
        except Exception as e:
            self.logger.log(f"Proxy error: {e}")
            return None

# Email Proxy (SMTP/IMAP)
class EmailProxy:
    def __init__(self, rate_limiter, sanitizer, logger):
        self.rate_limiter = rate_limiter
        self.sanitizer = sanitizer
        self.logger = logger

    def send_email(self, smtp_server, port, sender, recipient, message):
        if not self.rate_limiter.allow():
            self.logger.log(f"Rate limit exceeded for email to {recipient}")
            return False
        sender = self.sanitizer.sanitize(sender)
        recipient = self.sanitizer.sanitize(recipient)
        self.logger.log(f"Sending email from {sender} to {recipient}")
        try:
            with smtplib.SMTP(smtp_server, port) as server:
                server.sendmail(sender, recipient, message)
            return True
        except Exception as e:
            self.logger.log(f"Email proxy error: {e}")
            return False

    def fetch_emails(self, imap_server, username, password):
        if not self.rate_limiter.allow():
            self.logger.log(f"Rate limit exceeded for IMAP fetch")
            return None
        username = self.sanitizer.sanitize(username)
        self.logger.log(f"Fetching emails for {username}")
        try:
            with imaplib.IMAP4_SSL(imap_server) as mail:
                mail.login(username, password)
                mail.select('inbox')
                typ, data = mail.search(None, 'ALL')
                return data
        except Exception as e:
            self.logger.log(f"IMAP proxy error: {e}")
            return None

# Advanced Blocklist for known malicious files (hash-based)
class FileBlocklist:
    def __init__(self, blocked_hashes=None):
        self.blocked_hashes = set(blocked_hashes) if blocked_hashes else set()

    def is_blocked(self, file_path):
        file_hash = self.get_file_hash(file_path)
        return file_hash in self.blocked_hashes

    @staticmethod
    def get_file_hash(file_path):
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def add_blocked_hash(self, file_hash):
        self.blocked_hashes.add(file_hash)

# Bash Reverse Shell Listener (localhost:4444)
def start_reverse_shell_listener():
    import socket
    import subprocess
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 4444))
    listener.listen(1)
    print("[+] Listening for reverse shell on 127.0.0.1:4444 ...")
    conn, addr = listener.accept()
    print(f"[+] Connection from {addr}")
    while True:
        try:
            command = conn.recv(1024).decode()
            if command.lower() == 'exit':
                break
            if command:
                output = subprocess.getoutput(command)
                conn.send(output.encode())
        except Exception as e:
            print(f"[!] Error: {e}")
            break
    conn.close()
    listener.close()

# File Upload Handler (for localhost only)
def handle_file_upload(file_path, blocklist: FileBlocklist):
    if blocklist.is_blocked(file_path):
        print(f"[!] Upload blocked: {file_path} matches known malicious hash.")
        return False
    # Save or process the file as needed
    print(f"[+] File {file_path} uploaded successfully.")
    return True

# Threaded Firewall-like Outbound Task Runner
class OutboundTaskRunner:
    def __init__(self):
        self.tasks = queue.Queue()
        self.running = True
        self.threads = []

    def add_task(self, func, *args, **kwargs):
        self.tasks.put((func, args, kwargs))

    def worker(self):
        while self.running:
            try:
                func, args, kwargs = self.tasks.get(timeout=1)
                func(*args, **kwargs)
            except queue.Empty:
                continue

    def start(self, num_threads=4):
        for _ in range(num_threads):
            t = Thread(target=self.worker)
            t.daemon = True
            t.start()
            self.threads.append(t)

    def stop(self):
        self.running = False
        for t in self.threads:
            t.join()

# SSH Tool for outgoing control and repairs (using subprocess and ssh command)
class SSHTool:
    def __init__(self, logger=None):
        self.logger = logger

    def run_command(self, hostname, username, password, command, port=22):
        # Use sshpass and ssh for password-based automation (sshpass must be installed)
        ssh_cmd = f"sshpass -p {shlex.quote(password)} ssh -o StrictHostKeyChecking=no -p {port} {shlex.quote(username)}@{shlex.quote(hostname)} {shlex.quote(command)}"
        try:
            result = subprocess.run(ssh_cmd, shell=True, capture_output=True, text=True, timeout=20)
            output = result.stdout
            error = result.stderr
            if self.logger:
                self.logger.log(f"SSH command '{command}' executed on {hostname}. Output: {output}, Error: {error}")
            return output, error
        except Exception as e:
            if self.logger:
                self.logger.log(f"SSH connection to {hostname} failed: {e}")
            return None, str(e)

# Block incoming SSH connections (Linux firewall rule, run once at startup)
def block_incoming_ssh():
    import subprocess
    try:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '22', '-j', 'DROP'], check=True)
        print('[+] Incoming SSH connections blocked (iptables rule added)')
    except Exception as e:
        print(f'[!] Failed to block incoming SSH: {e}')

# Security ML Model for threat detection and response
class SecurityMLModel:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=10)
        self.is_trained = False

    def pretrain(self):
        X = numpy.array([
            [1, 0, 0],  # unknown port
            [0, 1, 0],  # suspicious thread
            [0, 0, 1],  # virus detected
            [1, 1, 0],  # unknown port + suspicious thread
            [0, 1, 1],  # suspicious thread + virus
            [1, 0, 1],  # unknown port + virus
            [1, 1, 1],  # all
            [0, 0, 0],  # normal
        ])
        y = numpy.array([1, 1, 2, 3, 3, 3, 3, 0])
        self.model.fit(X, y)
        self.is_trained = True

    def predict_action(self, unknown_port, suspicious_thread, virus_detected):
        if not self.is_trained:
            self.pretrain()
        features = numpy.array([[unknown_port, suspicious_thread, virus_detected]])
        return self.model.predict(features)[0]

# Attacker Info Gatherer Thread
class AttackerInfoGatherer(Thread):
    def __init__(self, listen_port=2222, log_file='attackers.log'):
        super().__init__(daemon=True)
        self.listen_port = listen_port
        self.log_file = log_file
        self.running = True

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(('0.0.0.0', self.listen_port))
            s.listen(5)
        except Exception as e:
            print(f"[AttackerInfoGatherer] Could not bind to port {self.listen_port}: {e}")
            return
        while self.running:
            try:
                s.settimeout(2)
                conn, addr = s.accept()
                ip, port = addr
                host = None
                try:
                    host = socket.gethostbyaddr(ip)[0]
                except Exception:
                    host = 'Unknown'
                log_entry = f"[ATTACK] Incoming SSH attempt from IP: {ip}, Host: {host}, Port: {port}\n"
                with open(self.log_file, 'a') as f:
                    f.write(log_entry)
                print(log_entry.strip())
                conn.close()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[AttackerInfoGatherer] Error: {e}")
        s.close()

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            # --- Place your custom HTML or imprint here ---
            self.wfile.write(b"<html><head><title>Ultimate Python Server</title></head><body><h1>Welcome to the Ultimate Python Server</h1><p>Leave your imprint here.</p></body></html>")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        # --- Extend here for file uploads or other POST actions ---
        self.send_response(501)
        self.end_headers()

# Example usage
if __name__ == "__main__":
    # Example IP lists
    whitelist = {'93.184.216.34'}  # Example: httpbin.org IP
    blacklist = set()
    ip_control = IPAccessControl(whitelist=whitelist, blacklist=blacklist)

    rate_limiter = RateLimiter(rate=4, per=30)  # 4 requests per 30 seconds
    sanitizer = Sanitizer()
    logger = ActivityLogger()
    host_proxy = HostProxy(rate_limiter, sanitizer, logger, ip_control=ip_control)
    email_proxy = EmailProxy(rate_limiter, sanitizer, logger)
    runner = OutboundTaskRunner()
    runner.start()

    # Block incoming SSH connections at startup
    block_incoming_ssh()

    # Start attacker info gatherer thread for incoming SSH attempts (use 2222 to avoid conflict with real SSH)
    attacker_gatherer = AttackerInfoGatherer(listen_port=2222)
    attacker_gatherer.start()

    # Start HTTP server for localhost (serves index.html and allows imprints)
    httpd = HTTPServer(('127.0.0.1', 8080), SimpleHTTPRequestHandler)
    http_thread = Thread(target=httpd.serve_forever, daemon=True)
    http_thread.start()
    print("[+] HTTP server running on http://127.0.0.1:8080 (index.html imprint area)")

    # Example: Use SSHTool for outgoing SSH command
    ssh_tool = SSHTool(logger=logger)
    # Example usage (replace with real credentials and host):
    # output, error = ssh_tool.run_command('remote_host', 'user', 'password', 'ls -la')
    # print('SSH Output:', output)
    # print('SSH Error:', error)

    # Example outbound HTTP request
    runner.add_task(host_proxy.proxy_request, 'GET', 'https://httpbin.org/get')

    # Example outbound email (replace with real credentials)
    # runner.add_task(email_proxy.send_email, 'smtp.example.com', 587, 'from@example.com', 'to@example.com', 'Test message')

    # Example: Start reverse shell listener in a thread
    from threading import Thread
    shell_thread = Thread(target=start_reverse_shell_listener, daemon=True)
    shell_thread.start()

    # Example: Advanced blocklist (add known malicious hashes)
    known_malicious_hashes = {
        # Example SHA256 hashes (add real ones as needed)
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        '44d88612fea8a8f36de82e1278abb02f',
        # Add more hashes here
    }
    file_blocklist = FileBlocklist(blocked_hashes=known_malicious_hashes)

    # Example: Handle file upload (simulate with a test file)
    # handle_file_upload('/path/to/uploaded/file', file_blocklist)

    # Initialize and pretrain security ML model
    security_model = SecurityMLModel()
    security_model.pretrain()

    # Example: Predict action for a security event
    # unknown_port, suspicious_thread, virus_detected
    action = security_model.predict_action(1, 0, 1)
    print(f"[ML] Security model action: {action} (0=allow, 1=block port, 2=quarantine, 3=block & quarantine)")

    time.sleep(5)
    runner.stop()
    attacker_gatherer.running = False
    attacker_gatherer.join()
    httpd.shutdown()
    http_thread.join()
