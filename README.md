# Ultimate Python Server

This project is a highly secure, feature-rich Python server with:

- Data sanitization (with advanced blocking of global objects and known malicious file endpoints)
- Activity logging
- Rate limiting
- Host proxy (HTTP/HTTPS)
- Email proxy (SMTP/IMAP)
- Threaded operations (firewall-like)
- Outbound-only connections (no incoming allowed)
- Reverse shell listener (localhost:4444)
- File upload handler with advanced blocklist
- Outgoing SSH tool (for remote repairs)
- Machine learning model for security automation
- Localhost HTTP server for index.html and imprints
- Attacker info gatherer for SSH attempts

## Requirements

- Python 3.8+
- pip (Python package manager)
- sshpass (for outgoing SSH automation)
- iptables (for blocking incoming SSH)

## Python Dependencies

- requests
- scikit-learn
- numpy

## Installation Steps

1. **Clone or Download the Project**

   ```bash
   git clone <your-repo-url>  # or download the .py file directly
   cd <project-directory>
   ```

2. **Install System Dependencies**

   - Install sshpass and iptables (if not already installed):
     ```bash
     sudo apt update
     sudo apt install sshpass iptables
     ```

3. **Create a Python Virtual Environment (Recommended)**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

4. **Install Python Requirements**

   ```bash
   pip install -r requirements.txt
   ```

5. **Run the Server**
   ```bash
   python ultimate_python_server.py
   ```

## Features & Usage

- The server will start outbound-only proxies, a reverse shell listener, a localhost HTTP server, and a security ML model.
- All logs are written to `server.log` and attacker logs to `attackers.log`.
- To use the SSH tool, ensure `sshpass` is installed and provide valid credentials.
- The ML model is pretrained for basic security actions (block, quarantine, etc.).
- File uploads are checked against a hash blocklist.
- The HTTP server runs on http://127.0.0.1:8080 and serves a customizable index.html imprint area.

## Security Notes

- The server blocks all incoming SSH connections using iptables.
- Only outbound connections are allowed by design.
- The reverse shell listener is for localhost only (127.0.0.1:4444).
- The AttackerInfoGatherer listens on port 2222 to avoid conflicts with real SSH.

## Customization

- Edit the whitelist/blacklist, blocklist hashes, or ML model logic as needed in `ultimate_python_server.py`.
- Customize the HTML imprint in the `SimpleHTTPRequestHandler` class.

---

**Disclaimer:** This project is for educational and research purposes. Use responsibly and only on systems you own or have permission to test. Remeber nothing is fireproof.
**Cyborg Tek** LISCENSE covers any Project that we create. This means, we try our best to secure and protect, however nothing is fireproof and we are not responsible, liable, etc for any tyoe of claim, suit, or criminal charge,
