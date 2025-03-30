#!/usr/bin/env python3
"""
Dataiku-specific SSH key manager that works around permission issues.
This script creates and manages SSH keys using Python's file operations
rather than relying on system commands that might be restricted.
"""

import os
import base64
import random
import string
import subprocess
import getpass
import socket
from pathlib import Path
import sys

# ANSI Colors
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
RED = '\033[0;31m'
CYAN = '\033[0;36m'
RESET = '\033[0m'

# User's home directory
HOME = str(Path.home())
SSH_DIR = os.path.join(HOME, '.ssh')
PYTHON_KEY_DIR = os.path.join(HOME, '.python_keys')
KEY_PEM_FILE = os.path.join(PYTHON_KEY_DIR, 'private_key.pem')
KEY_PUB_FILE = os.path.join(PYTHON_KEY_DIR, 'public_key.txt')
KEY_SCRIPT = os.path.join(PYTHON_KEY_DIR, 'use_key.py')

def print_header():
    """Print header with nice formatting"""
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}            Dataiku-specific SSH Key Manager{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"Username: {GREEN}{getpass.getuser()}{RESET}")
    print(f"Hostname: {GREEN}{socket.gethostname()}{RESET}")
    print(f"Python version: {GREEN}{sys.version.split()[0]}{RESET}")

def setup_directory_structure():
    """Create necessary directories"""
    if not os.path.exists(PYTHON_KEY_DIR):
        os.makedirs(PYTHON_KEY_DIR, exist_ok=True)
        print(f"{GREEN}Created Python key directory at {PYTHON_KEY_DIR}{RESET}")
    
    if not os.path.exists(SSH_DIR):
        os.makedirs(SSH_DIR, exist_ok=True)
        print(f"{GREEN}Created SSH directory at {SSH_DIR}{RESET}")

def generate_rsa_keypair():
    """Generate an RSA key pair using Python's built-in capabilities"""
    if os.path.exists(KEY_PEM_FILE) and os.path.exists(KEY_PUB_FILE):
        print(f"{YELLOW}Key files already exist at {PYTHON_KEY_DIR}{RESET}")
        return True
    
    try:
        # Try to use cryptography package if available
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            
            print("Generating 2048-bit RSA key with cryptography...")
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize private key
            pem_private = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            # Serialize public key in OpenSSH format
            ssh_public = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            ).decode('utf-8')
            
            # Add comment to public key
            ssh_public = f"{ssh_public} {getpass.getuser()}@{socket.gethostname()}"
            
        except ImportError:
            # Fallback to generating a placeholder key and instructions if cryptography not available
            print(f"{YELLOW}Cryptography package not available. Using placeholder key.{RESET}")
            print(f"{YELLOW}For a real key, run: pip install --user cryptography and run this script again.{RESET}")
            
            # Generate a placeholder private key (warning: this is NOT secure, just for demo)
            pem_private = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxzYkEkKyWqEMyhU7WNcZ54KOfUJ3yQEJf0uuAQL/uJ+j+pWm
58nGE7q1TqTHPgm9UgMUbXWtZOEJwMBq0RXi8sST5hSc5hz/l43Rj7Q/Eb9xO8+k
0Ewpe4gkTkSXRLYP8rRbHrj+N/fM7HhOBM18fgKTwOCW9fUfJLOES65f67OKzfWJ
+5rXwAqbOKgKF/j/R0NLmoATD7fXZCIN68YQ986QtJKOLrO0CKOUmj25yrYGY2RF
YpQZDDzxw9iYELsKmQzqXsbCRJ+2x8xC0KNG4GXQBuIQZ9D3MLx2HpIVXhuuBFGx
fMgFAfJQXKz5vSP0JnaPM0NxG7hQVnSsOu0v9QIDAQABAoIBAQC9aLKuEFpDyT+o
F86XtLZHKRoV5TZLdVGUO0wdOHVZ2lfzUCz9nrFwH8XaiVTY1kRzcIMIE8BZpKjz
pK5zKgoRGD5h2yb8ZW0d3eur1vFhirvNBTj0RQx65pVslgQX9cHIkQFk+W6wS5XV
T7EgyPNEVwWJgmwpBQQafG8fEG0qk5EKl1f+FDmO70rFd5Zrr4ap5S4ee0qKFbq6
hLnj5IkUg2J0YHbyQ6tkSgq8QTlnUo9PfZ7jGpGpTChmYRTIHXbz3C4iCsVW/Ih5
hc3SIOcpEKwVtNZkdZ8g2WXqYxAWrC8ZTZxUiKHo9e5UtmQpz2eJ5Wrv10MP6+8G
cFKm0EqdAoGBAOmvBf/Tgqc69I/xcuUXFUMF19isMnQvzdHk0cyKNJLb8wLkUvPo
fQSQyHJzMJ8bOc3P8h+qFwcBKPEyqpSER2Pv5CIrfR51cy2PKN5uNkTYJUV+kJS1
4TdklZDrwyHbGWGBQJIfuXdqDPkQ9a13qjqMQpDI9gyHuTJg15gzRqzDAoGBANrN
JJgh8dwOdrnvfAcV55mNHrMUvU1wAImgrp1kwoFXTVrZKQnELJxzPE8B55Oxc5Mu
ABJmLKqsG0jMXOB4C8ZrhI/FPzZP21apcEU08BO1Nr+/PBIx/wJWbfoEnAIHcYBP
MF69x08XZjvBXhvMNQtEkQWfbKLIoauG/8vgRk/HAoGAA3FmV8T6XuVn4l9XuQcy
+0yimXbkQINrvC9C4JBRmekiW88GCepJbgY0zO0JLtPx5D0hVTZNV5TCtjU8tTTp
OR2G/InmTRKDzYpBFfTwmTFYZwVJCmcHdoplHvskQq6WP9SdfjujWa1G1Fvon8uT
jyVLXPWPtVP1VdGKpHOd1bUCgYEAx38Qj7rHt+BoaWjrH3eeK2RQFki+dV1tzpkH
J9tqAFrHoBjBWkcJkRfK2H5/92kpaFCx4d38oz4a4fgYZgNJB5u05Qmm0Qj5C0q7
YlJIgQMkTKtQqg2tN5PQQr9Uk5HFdF6NEjrsBFETzbfOIGpnvLQwLHcZaHjGrMCN
mMvBuV8CgYBmgErM+cxW0rDnKClsAYnUHAzpRhAIOHwC1b4r63PhtJXcQJN0/rI2
z1JlkzKEp5TUQ46jKwqf/bbCaS3OfX29N3/t0+G3zDs/p1meV33IR+4SNHoRRPRI
3nnHVtRbRY5hEEFe9UBy+tFJnoe+Is5JkPOCmPYE1X1/2I81OvHv4g==
-----END RSA PRIVATE KEY-----"""
            
            ssh_public = f"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHNiQSQrJaoQzKFTtY1xnng0U9QnfJAQl/S64BAv+4n6P6labnyYYTurVOpMc+Cb1SAxRtda1k4QnAwGrRFeLyxJPmFJzmHP+XjdGPtD8Rv3E7z6TQTCW7iCRORJdEtg/ytFseuP4398zseE4EzXx+ApPA4Jb19R8ks4RLrl/rs4rN9Yn7mtfACps4qAoX+P9HQ0uagBMPt9dkIg3rxhD3zpC0ko4us7QIo5SaPbnKtgZjZEVilBkMPPHD2JgQuwqZDOpexsJEn7bHzELQo0bgZdAG4hBn0PcwvHYekhVeG64EUbF8yAUB8lBcrPm9I/QmJo8zQ3UbuFBWdKw7PT/1 {getpass.getuser()}@{socket.gethostname()}"
        
        # Write the keys to files
        with open(KEY_PEM_FILE, 'w') as f:
            f.write(pem_private)
        
        with open(KEY_PUB_FILE, 'w') as f:
            f.write(ssh_public)
        
        print(f"{GREEN}Generated key pair:{RESET}")
        print(f"{GREEN}  - Private key: {KEY_PEM_FILE}{RESET}")
        print(f"{GREEN}  - Public key: {KEY_PUB_FILE}{RESET}")
        
        # Create a symbolic link in the .ssh directory if possible
        try:
            key_link = os.path.join(SSH_DIR, 'id_rsa_python')
            if not os.path.exists(key_link):
                os.symlink(KEY_PEM_FILE, key_link)
                print(f"{GREEN}Created symbolic link: {key_link} -> {KEY_PEM_FILE}{RESET}")
            
            pubkey_link = os.path.join(SSH_DIR, 'id_rsa_python.pub')
            if not os.path.exists(pubkey_link):
                os.symlink(KEY_PUB_FILE, pubkey_link)
                print(f"{GREEN}Created symbolic link: {pubkey_link} -> {KEY_PUB_FILE}{RESET}")
        except OSError as e:
            print(f"{YELLOW}Could not create symbolic links: {e}{RESET}")
            print(f"{YELLOW}This is normal in some environments. The keys will still work.{RESET}")
        
        return True
    except Exception as e:
        print(f"{RED}Error generating key pair: {e}{RESET}")
        return False

def create_key_usage_script():
    """Create a script to use the keys for SSH and Git operations"""
    script_content = f"""#!/usr/bin/env python3
import os
import sys
import subprocess
import tempfile

# Key file paths
KEY_PEM_FILE = "{KEY_PEM_FILE}"
KEY_PUB_FILE = "{KEY_PUB_FILE}"

def run_ssh_command():
    \"\"\"Run an SSH command using the private key\"\"\"
    if len(sys.argv) < 2:
        print("Usage: python use_key.py <ssh_command> [args...]")
        print("Example: python use_key.py ssh user@hostname")
        sys.exit(1)
    
    # Create a temporary SSH control file
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(f"IdentityFile {KEY_PEM_FILE}\\n")
        f.write("StrictHostKeyChecking no\\n")
        f.write("UserKnownHostsFile /dev/null\\n")
        control_file = f.name
    
    # Build the command
    cmd = sys.argv[1:]
    if cmd[0] == "ssh" or cmd[0] == "scp" or cmd[0] == "sftp":
        cmd.insert(1, "-F")
        cmd.insert(2, control_file)
    elif cmd[0] == "git":
        os.environ["GIT_SSH_COMMAND"] = f"ssh -F {control_file}"
    
    try:
        # Run the command
        process = subprocess.Popen(cmd)
        process.wait()
    finally:
        # Clean up the temporary file
        try:
            os.unlink(control_file)
        except:
            pass

if __name__ == "__main__":
    run_ssh_command()
"""
    
    script_path = os.path.join(PYTHON_KEY_DIR, 'use_key.py')
    with open(script_path, 'w') as f:
        f.write(script_content)
    
    os.chmod(script_path, 0o755)
    print(f"{GREEN}Created key usage script: {script_path}{RESET}")
    return script_path

def create_ssh_config():
    """Create an SSH config file that uses our key"""
    config_file = os.path.join(SSH_DIR, 'config')
    config_content = f"""# SSH Configuration for Python-generated keys
# Created by dataiku_key.py

Host github.com
    User git
    IdentityFile {KEY_PEM_FILE}
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

# Global settings
Host *
    IdentityFile {KEY_PEM_FILE}
    ServerAliveInterval 60
    ServerAliveCountMax 30
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
"""
    
    with open(config_file, 'w') as f:
        f.write(config_content)
    
    print(f"{GREEN}Created SSH config file: {config_file}{RESET}")
    return config_file

def create_terminal_script():
    """Create a simple Python-based terminal emulator"""
    terminal_script = os.path.join(HOME, 'python_terminal.py')
    terminal_content = """#!/usr/bin/env python3
import os
import sys
import subprocess
import readline
import rlcompleter

print("Starting Python Terminal Emulator")
print("You can run shell commands with os.system() or !command syntax")
print("Examples:")
print("  os.system('ls -la')")
print("  !ls -la")
print("  !git status")
print("Exit with exit() or Ctrl+D")

# Enable tab completion
readline.parse_and_bind("tab: complete")

# Add support for shell command syntax
class ShellExecutor:
    def __repr__(self):
        return ""
    
    def __call__(self, cmd):
        return os.system(cmd)

# Create ! syntax for shell commands
import __main__
__main__.__builtins__['!'] = ShellExecutor()

# Start interactive shell
import code
code.interact(local=locals())
"""
    
    with open(terminal_script, 'w') as f:
        f.write(terminal_content)
    
    os.chmod(terminal_script, 0o755)
    print(f"{GREEN}Created Python terminal emulator: {terminal_script}{RESET}")
    return terminal_script

def print_instructions(key_script, terminal_script):
    """Print usage instructions"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}                  Key Usage Instructions{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    # Show public key
    print(f"{YELLOW}Your SSH public key:{RESET}")
    try:
        with open(KEY_PUB_FILE, 'r') as f:
            pub_key = f.read().strip()
            print(f"{GREEN}{pub_key}{RESET}")
    except:
        print(f"{RED}Could not read public key.{RESET}")
    
    print(f"\n{YELLOW}For SSH operations:{RESET}")
    print(f"  Connect to server:    {GREEN}!python3 {key_script} ssh username@hostname{RESET}")
    print(f"  Copy to server:       {GREEN}!python3 {key_script} scp file.txt username@hostname:/path/{RESET}")
    print(f"  Copy from server:     {GREEN}!python3 {key_script} scp username@hostname:/path/file.txt ./{RESET}")
    
    print(f"\n{YELLOW}For Git operations:{RESET}")
    print(f"  Clone repository:     {GREEN}!python3 {key_script} git clone git@github.com:username/repo.git{RESET}")
    print(f"  Push changes:         {GREEN}!python3 {key_script} git push origin main{RESET}")
    
    print(f"\n{YELLOW}For a terminal emulator:{RESET}")
    print(f"  Start terminal:       {GREEN}!python3 {terminal_script}{RESET}")
    
    print(f"\n{YELLOW}Key locations:{RESET}")
    print(f"  Private key:          {GREEN}{KEY_PEM_FILE}{RESET}")
    print(f"  Public key:           {GREEN}{KEY_PUB_FILE}{RESET}")
    print(f"  SSH config:           {GREEN}{os.path.join(SSH_DIR, 'config')}{RESET}")
    
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}                       Setup Complete{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")

def main():
    """Main function to set up SSH key handling"""
    print_header()
    setup_directory_structure()
    if generate_rsa_keypair():
        key_script = create_key_usage_script()
        create_ssh_config()
        terminal_script = create_terminal_script()
        print_instructions(key_script, terminal_script)
    else:
        print(f"{RED}Failed to set up SSH keys.{RESET}")

if __name__ == "__main__":
    main()