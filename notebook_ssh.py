#!/usr/bin/env python3
"""
One-line SSH access solution for notebook environments.
This script sets up an SSH environment without requiring sudo,
creates keys, and enables tunneling capabilities.
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
import json
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
        subprocess.run([
            'ssh-keygen', 
            '-t', 'rsa',
            '-b', '4096',
            '-C', f"{getpass.getuser()}@{socket.gethostname()}",
            '-f', key_file,
            '-N', ''  # Empty passphrase
        ], check=True)
        
        # Set permissions
        os.chmod(key_file, 0o600)
        os.chmod(f"{key_file}.pub", 0o644)
        
        print(f"{GREEN}SSH key generated at {key_file}{RESET}")
        with open(f"{key_file}.pub", 'r') as f:
            pub_key = f.read().strip()
            print(f"\nPublic key: {GREEN}{pub_key}{RESET}\n")
    except Exception as e:
        print(f"{RED}Failed to generate SSH key: {str(e)}{RESET}")

def install_sshx():
    """Install SSHX for tunneling capabilities"""
    sshx_path = os.path.join(BIN_DIR, 'sshx')
    
    if os.path.exists(sshx_path):
        print(f"{YELLOW}SSHX already installed at {sshx_path}{RESET}")
        try:
            version = subprocess.check_output([sshx_path, '--version'], text=True).strip()
            print(f"{GREEN}SSHX version: {version}{RESET}")
        except:
            print(f"{YELLOW}Could not determine SSHX version{RESET}")
        return
    
    # Detect architecture and download appropriate version
    arch = platform.machine()
    if arch == 'x86_64':
        url = "https://s3.amazonaws.com/sshx/sshx-x86_64-unknown-linux-musl.tar.gz"
    elif arch == 'aarch64':
        url = "https://s3.amazonaws.com/sshx/sshx-aarch64-unknown-linux-musl.tar.gz"
    else:
        print(f"{RED}Unsupported architecture: {arch}{RESET}")
        return
    
    # Download sshx
    tmp_dir = tempfile.mkdtemp()
    tar_path = os.path.join(tmp_dir, 'sshx.tar.gz')
    
    if download_file(url, tar_path):
        try:
            # Extract the tar file
            subprocess.run(['tar', '-xzf', tar_path, '-C', tmp_dir], check=True)
            
            # Move sshx to bin directory
            extracted_sshx = os.path.join(tmp_dir, 'sshx')
            if os.path.exists(extracted_sshx):
                os.rename(extracted_sshx, sshx_path)
                os.chmod(sshx_path, 0o755)
                print(f"{GREEN}Installed SSHX to {sshx_path}{RESET}")
                
                # Check version
                version = subprocess.check_output([sshx_path, '--version'], text=True).strip()
                print(f"{GREEN}SSHX version: {version}{RESET}")
            else:
                print(f"{RED}Could not find sshx in the extracted files{RESET}")
        except Exception as e:
            print(f"{RED}Failed to extract and install SSHX: {str(e)}{RESET}")
    
    # Clean up temp directory
    try:
        import shutil
        shutil.rmtree(tmp_dir)
    except:
        pass

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

def test_ssh_connectivity():
    """Test SSH connectivity to GitHub"""
    print("\nTesting SSH connectivity to GitHub...")
    try:
        result = subprocess.run(
            ['ssh', '-T', 'git@github.com', '-o', 'StrictHostKeyChecking=no'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        
        if "successfully authenticated" in result.stderr:
            print(f"{GREEN}SSH connection to GitHub successful!{RESET}")
            return True
        else:
            print(f"{YELLOW}SSH connection test output: {result.stderr}{RESET}")
            return False
    except Exception as e:
        print(f"{RED}SSH connection test failed: {str(e)}{RESET}")
        return False

def setup_sshx_tunnel(port=8022):
    """Set up an SSH tunnel using SSHX"""
    sshx_path = os.path.join(BIN_DIR, 'sshx')
    if not os.path.exists(sshx_path):
        print(f"{RED}SSHX not installed, cannot set up tunnel{RESET}")
        return
    
    print(f"\n{CYAN}SSHX Tunneling Options:{RESET}")
    print(f"To create a tunnel, run the following command in a new cell:")
    print(f"{GREEN}!{sshx_path} create --name my-tunnel{RESET}")
    
    print(f"\nTo list your tunnels:")
    print(f"{GREEN}!{sshx_path} list{RESET}")
    
    print(f"\nTo connect to a tunnel:")
    print(f"{GREEN}!{sshx_path} connect my-tunnel{RESET}")
    
    print(f"\nFor reverse tunneling (allow connections to this notebook):")
    print(f"{GREEN}!{sshx_path} serve --port {port}{RESET}")

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
    
    sshx_path = os.path.join(BIN_DIR, 'sshx')
    if os.path.exists(sshx_path):
        print(f"\n{YELLOW}SSHX Commands:{RESET}")
        print(f"  Create a tunnel:                  {GREEN}!{sshx_path} create --name my-tunnel{RESET}")
        print(f"  Connect to a tunnel:              {GREEN}!{sshx_path} connect my-tunnel{RESET}")
        print(f"  Serve this notebook (rev tunnel): {GREEN}!{sshx_path} serve --port 8022{RESET}")
    
    print(f"\n{YELLOW}To modify SSH config:{RESET}")
    print(f"  Edit the file at:                 {GREEN}{os.path.join(SSH_DIR, 'config')}{RESET}")
    
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}                       Setup Complete{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")

def main():
    """Main function to set up SSH access"""
    print_header()
    setup_directory_structure()
    generate_ssh_key()
    create_ssh_config()
    install_sshx()
    test_ssh_connectivity()
    setup_sshx_tunnel()
    print_instructions()

if __name__ == "__main__":
    main()