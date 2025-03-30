#!/usr/bin/env python3
"""
One-line SSH access solution for notebook environments.
This script sets up an SSH environment without requiring sudo,
creates keys, and enables terminal access via various methods.
"""

import os
import sys
import platform
import subprocess
import tempfile
import base64
import random
import string
import socket
import time
from pathlib import Path
import urllib.request
import getpass

# ANSI Colors for pretty output
CYAN = '\033[0;36m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
RED = '\033[0;31m'
RESET = '\033[0m'

# User's home directory
HOME = str(Path.home())
SSH_DIR = os.path.join(HOME, '.ssh')
BIN_DIR = os.path.join(HOME, 'bin')

def print_header():
    """Print header with nice formatting"""
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}                SSH Access for Notebook Environments{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"Username: {GREEN}{getpass.getuser()}{RESET}")
    print(f"Hostname: {GREEN}{socket.gethostname()}{RESET}")
    print(f"Working directory: {GREEN}{os.getcwd()}{RESET}")
    print(f"Platform: {GREEN}{platform.platform()}{RESET}")

def download_file(url, target_path):
    """Download a file with progress indication"""
    print(f"Downloading {url}...")
    try:
        with urllib.request.urlopen(url) as response, open(target_path, 'wb') as out_file:
            file_size = int(response.headers.get('Content-Length', 0))
            downloaded = 0
            chunk_size = 8192
            
            while True:
                chunk = response.read(chunk_size)
                if not chunk:
                    break
                downloaded += len(chunk)
                out_file.write(chunk)
                
                # Show progress for larger files
                if file_size > 100000:
                    percent = int(100 * downloaded / file_size)
                    sys.stdout.write(f"\rProgress: {percent}% ({downloaded}/{file_size} bytes)")
                    sys.stdout.flush()
            
            if file_size > 100000:
                print()  # New line after progress bar
                
        print(f"{GREEN}Download complete: {target_path}{RESET}")
        return True
    except Exception as e:
        print(f"{RED}Download failed: {str(e)}{RESET}")
        return False

def setup_directory_structure():
    """Create necessary directories"""
    # Create .ssh directory if it doesn't exist
    if not os.path.exists(SSH_DIR):
        os.makedirs(SSH_DIR, exist_ok=True)
        os.chmod(SSH_DIR, 0o700)
        print(f"{GREEN}Created SSH directory at {SSH_DIR}{RESET}")
    
    # Create bin directory for tools
    if not os.path.exists(BIN_DIR):
        os.makedirs(BIN_DIR, exist_ok=True)
        print(f"{GREEN}Created bin directory at {BIN_DIR}{RESET}")
    
    # Add bin to PATH if not already there
    bin_in_path = BIN_DIR in os.environ.get('PATH', '')
    if not bin_in_path:
        os.environ['PATH'] = f"{BIN_DIR}:{os.environ.get('PATH', '')}"
        print(f"{GREEN}Added {BIN_DIR} to PATH{RESET}")

def generate_ssh_key():
    """Generate an SSH key if one doesn't exist"""
    key_file = os.path.join(SSH_DIR, 'id_rsa')
    if os.path.exists(key_file):
        print(f"{YELLOW}SSH key already exists at {key_file}{RESET}")
        return
    
    print("Generating new SSH key...")
    try:
        # Generate key non-interactively
        subprocess.call([
            'ssh-keygen', 
            '-t', 'rsa',
            '-b', '4096',
            '-C', f"{getpass.getuser()}@{socket.gethostname()}",
            '-f', key_file,
            '-N', ''  # Empty passphrase
        ])
        
        # Set permissions
        os.chmod(key_file, 0o600)
        os.chmod(f"{key_file}.pub", 0o644)
        
        print(f"{GREEN}SSH key generated at {key_file}{RESET}")
        with open(f"{key_file}.pub", 'r') as f:
            pub_key = f.read().strip()
            print(f"\nPublic key: {GREEN}{pub_key}{RESET}\n")
    except Exception as e:
        print(f"{RED}Failed to generate SSH key: {str(e)}{RESET}")

def create_ssh_config():
    """Create a basic SSH config file if one doesn't exist"""
    config_file = os.path.join(SSH_DIR, 'config')
    if os.path.exists(config_file):
        print(f"{YELLOW}SSH config already exists at {config_file}{RESET}")
        return
    
    print("Creating SSH config file...")
    try:
        with open(config_file, 'w') as f:
            f.write("""# SSH Configuration File
# Created automatically by notebook_ssh.py

Host github.com
    User git
    IdentityFile ~/.ssh/id_rsa
    
# Example server configuration
# Host example-server
#     HostName example.com
#     User username
#     IdentityFile ~/.ssh/id_rsa
#     Port 22
            
# Global settings
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 30
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
""")
        
        os.chmod(config_file, 0o600)
        print(f"{GREEN}SSH config created at {config_file}{RESET}")
    except Exception as e:
        print(f"{RED}Failed to create SSH config: {str(e)}{RESET}")

def create_terminal_access_script():
    """Create a script to start a terminal service in the notebook"""
    terminal_script = os.path.join(HOME, 'start_terminal.py')
    try:
        with open(terminal_script, 'w') as f:
            f.write("""#!/usr/bin/env python3
import os
import socket
import subprocess
import threading
import time
import sys

# Get free port
def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port

# Get your public IP
hostname = socket.gethostname()
try:
    local_ip = socket.gethostbyname(hostname)
except:
    local_ip = "127.0.0.1"  # Fallback

ssh_port = get_free_port()
print(f"Starting terminal service on {local_ip}:{ssh_port}")

# Setup SSH configuration
ssh_dir = os.path.expanduser("~/.ssh")
if not os.path.exists(ssh_dir):
    os.makedirs(ssh_dir, mode=0o700)

# Add public key to authorized_keys if it exists
key_file = os.path.join(ssh_dir, 'id_rsa.pub')
if os.path.exists(key_file):
    with open(key_file, 'r') as f:
        pubkey = f.read().strip()
    
    auth_keys = os.path.join(ssh_dir, 'authorized_keys')
    with open(auth_keys, 'w') as f:
        f.write(pubkey + "\\n")
    
    os.chmod(auth_keys, 0o600)
    print(f"Added your public key to {auth_keys}")

# Try different terminal methods
methods = ['tty-share', 'ttyd', 'shellinabox', 'sshd']
success = False

for method in methods:
    if method == 'tty-share' and subprocess.call(['which', 'tty-share'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
        print("Starting terminal with tty-share...")
        try:
            subprocess.Popen(['tty-share', '-p', str(ssh_port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"Terminal ready at: http://{local_ip}:{ssh_port}")
            success = True
            break
        except Exception as e:
            print(f"Failed to start tty-share: {e}")
    
    elif method == 'ttyd' and subprocess.call(['which', 'ttyd'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
        print("Starting terminal with ttyd...")
        try:
            subprocess.Popen(['ttyd', '-p', str(ssh_port), 'bash'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"Terminal ready at: http://{local_ip}:{ssh_port}")
            success = True
            break
        except Exception as e:
            print(f"Failed to start ttyd: {e}")
    
    elif method == 'shellinabox' and subprocess.call(['which', 'shellinaboxd'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
        print("Starting terminal with shellinabox...")
        try:
            subprocess.Popen(['shellinaboxd', '--no-beep', '-p', str(ssh_port), '-t'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"Terminal ready at: http://{local_ip}:{ssh_port}")
            success = True
            break
        except Exception as e:
            print(f"Failed to start shellinabox: {e}")
    
    elif method == 'sshd' and subprocess.call(['which', 'sshd'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
        print("Starting SSH server...")
        # Create a minimal sshd_config
        config_path = os.path.expanduser("~/sshd_config")
        with open(config_path, "w") as f:
            f.write(f'''Port {ssh_port}
ListenAddress 0.0.0.0
HostKey {os.path.expanduser("~/.ssh/id_rsa")}
PubkeyAuthentication yes
PasswordAuthentication no
AuthorizedKeysFile {os.path.expanduser("~/.ssh/authorized_keys")}
Subsystem sftp internal-sftp
''')
        try:
            proc = subprocess.Popen(['sshd', '-f', config_path, '-D'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"SSH server started. Connect with: ssh -p {ssh_port} {os.getlogin()}@{local_ip}")
            print("Use your private key for authentication.")
            success = True
            break
        except Exception as e:
            print(f"Failed to start sshd: {e}")

if not success:
    # Create a Python-based shell if no other method works
    print("No terminal service available. Creating a simple Python shell...")
    
    import code
    import readline
    import rlcompleter
    
    # Setup tab completion
    readline.parse_and_bind("tab: complete")
    
    # Start a Python shell
    print("Python shell started. You can run commands with os.system() or subprocess.")
    print("For example: import os; os.system('ls -la')")
    code.interact(local=locals())

print("Press Ctrl+C to stop the service")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Terminal service stopped")
""")
        
        os.chmod(terminal_script, 0o755)
        print(f"{GREEN}Terminal access script created at {terminal_script}{RESET}")
        print(f"{YELLOW}Run it with: !python3 ~/start_terminal.py{RESET}")
        return True
    except Exception as e:
        print(f"{RED}Failed to create terminal script: {str(e)}{RESET}")
        return False

def test_github_connectivity():
    """Test SSH connectivity to GitHub"""
    print("\nTesting SSH connectivity to GitHub...")
    try:
        # Using subprocess.call instead of run for Python 3.6 compatibility
        result = subprocess.call(
            ['ssh', '-T', 'git@github.com', '-o', 'StrictHostKeyChecking=no'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        if result == 1:  # GitHub returns 1 for successful authentication
            print(f"{GREEN}SSH connection to GitHub successful!{RESET}")
            return True
        else:
            print(f"{YELLOW}SSH connection test returned code: {result}{RESET}")
            return False
    except Exception as e:
        print(f"{RED}SSH connection test failed: {str(e)}{RESET}")
        return False

def create_git_setup():
    """Set up Git configuration"""
    try:
        # Check if git is available
        if subprocess.call(['which', 'git'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) != 0:
            print(f"{YELLOW}Git not found in PATH. Skipping Git setup.{RESET}")
            return False
        
        # Set up Git configuration
        print("\nSetting up Git configuration...")
        username = getpass.getuser()
        hostname = socket.gethostname()
        
        subprocess.call(['git', 'config', '--global', 'user.name', username])
        subprocess.call(['git', 'config', '--global', 'user.email', f"{username}@{hostname}"])
        
        # Set up SSH for Git
        subprocess.call(['git', 'config', '--global', 'core.sshCommand', 'ssh -i ~/.ssh/id_rsa -o StrictHostKeyChecking=no'])
        
        print(f"{GREEN}Git configured successfully{RESET}")
        return True
    except Exception as e:
        print(f"{RED}Failed to set up Git: {str(e)}{RESET}")
        return False

def create_ssh_tunnel_script():
    """Create an SSH tunnel script using pure Python"""
    tunnel_script = os.path.join(HOME, 'ssh_tunnel.py')
    try:
        with open(tunnel_script, 'w') as f:
            f.write("""#!/usr/bin/env python3
import sys
import socket
import threading
import time
import os

def print_usage():
    print("SSH Tunnel - Pure Python Implementation")
    print("Usage:")
    print("  python ssh_tunnel.py local_port remote_host remote_port")
    print("Example:")
    print("  python ssh_tunnel.py 8080 example.com 80")
    print("  This will forward localhost:8080 to example.com:80")
    sys.exit(1)

if len(sys.argv) != 4:
    print_usage()

local_port = int(sys.argv[1])
remote_host = sys.argv[2]
remote_port = int(sys.argv[3])

print(f"Starting SSH tunnel: localhost:{local_port} -> {remote_host}:{remote_port}")

def handle_client(client_socket, remote_host, remote_port):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        remote_socket.connect((remote_host, remote_port))
        
        # Configure sockets for non-blocking operation
        client_socket.setblocking(False)
        remote_socket.setblocking(False)
        
        client_data = b""
        remote_data = b""
        
        while True:
            # Check for client -> remote data
            try:
                data = client_socket.recv(4096)
                if not data:
                    break
                remote_socket.sendall(data)
            except BlockingIOError:
                pass
            except:
                break
                
            # Check for remote -> client data
            try:
                data = remote_socket.recv(4096)
                if not data:
                    break
                client_socket.sendall(data)
            except BlockingIOError:
                pass
            except:
                break
                
            time.sleep(0.01)  # Small sleep to reduce CPU usage
    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        client_socket.close()
        remote_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(('0.0.0.0', local_port))
        server.listen(5)
        print(f"Listening on localhost:{local_port}")
        
        while True:
            client_sock, addr = server.accept()
            print(f"Received connection from {addr[0]}:{addr[1]}")
            
            client_handler = threading.Thread(
                target=handle_client,
                args=(client_sock, remote_host, remote_port)
            )
            client_handler.daemon = True
            client_handler.start()
            
    except KeyboardInterrupt:
        print("Tunnel stopped by user")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    main()
""")
        
        os.chmod(tunnel_script, 0o755)
        print(f"{GREEN}SSH tunnel script created at {tunnel_script}{RESET}")
        print(f"{YELLOW}Run it with: !python3 ~/ssh_tunnel.py local_port remote_host remote_port{RESET}")
        return True
    except Exception as e:
        print(f"{RED}Failed to create tunnel script: {str(e)}{RESET}")
        return False

def print_instructions():
    """Print usage instructions"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}                       Instructions{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    pub_key_path = os.path.join(SSH_DIR, 'id_rsa.pub')
    if os.path.exists(pub_key_path):
        with open(pub_key_path, 'r') as f:
            pub_key = f.read().strip()
        
        print(f"Your SSH public key:\n{GREEN}{pub_key}{RESET}\n")
        print("Add this key to servers or services you want to access.")
    
    print(f"\n{YELLOW}SSH Commands:{RESET}")
    print(f"  Connect to a server:              {GREEN}!ssh username@hostname{RESET}")
    print(f"  Copy files to a server:           {GREEN}!scp localfile.txt username@hostname:/path/{RESET}")
    print(f"  Copy files from a server:         {GREEN}!scp username@hostname:/path/file.txt ./{RESET}")
    
    print(f"\n{YELLOW}Git Commands:{RESET}")
    print(f"  Clone a private repository:       {GREEN}!git clone git@github.com:username/repo.git{RESET}")
    print(f"  Clone with explicit key:          {GREEN}!GIT_SSH_COMMAND=\"ssh -i ~/.ssh/id_rsa\" git clone git@github.com:username/repo.git{RESET}")
    
    print(f"\n{YELLOW}Terminal Access:{RESET}")
    print(f"  Start a terminal service:         {GREEN}!python3 ~/start_terminal.py{RESET}")
    
    print(f"\n{YELLOW}SSH Tunneling:{RESET}")
    print(f"  Create a tunnel:                  {GREEN}!python3 ~/ssh_tunnel.py 8080 example.com 80{RESET}")
    
    print(f"\n{YELLOW}To modify SSH config:{RESET}")
    print(f"  Edit the file at:                 {GREEN}{os.path.join(SSH_DIR, 'config')}{RESET}")
    
    print(f"\n{YELLOW}Your private key location:{RESET}")
    print(f"  Private key:                      {GREEN}{os.path.join(SSH_DIR, 'id_rsa')}{RESET}")
    print(f"  Public key:                       {GREEN}{os.path.join(SSH_DIR, 'id_rsa.pub')}{RESET}")
    
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}                       Setup Complete{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")

def main():
    """Main function to set up SSH access"""
    print_header()
    setup_directory_structure()
    generate_ssh_key()
    create_ssh_config()
    create_terminal_access_script()
    create_ssh_tunnel_script()
    create_git_setup()
    test_github_connectivity()
    print_instructions()

if __name__ == "__main__":
    main()