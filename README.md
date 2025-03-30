# SSH Access for Jupyter Notebooks

This repository provides a one-line solution for setting up SSH access in Jupyter notebooks and other restricted environments where you don't have sudo privileges.

## One-Line Solution

Copy and paste this single line into your Jupyter notebook cell to set up complete SSH access:

```python
!python3 -c "import urllib.request; exec(urllib.request.urlopen('https://raw.githubusercontent.com/malc3om/ssh-access/main/notebook_ssh.py').read().decode())"
```

## What This Does

This solution will:

1. Generate SSH keys if they don't exist
2. Set up proper SSH configuration
3. Download and install SSHX for tunneling capabilities
4. Test connectivity to GitHub
5. Provide instructions for using SSH and SSHX

## Features

- Works in environments without sudo/root access
- Creates SSH keys non-interactively
- Sets proper permissions on all SSH files
- Installs SSHX for advanced tunneling capabilities
- Works in Jupyter notebooks, Dataiku, Google Colab, etc.
- Provides clear instructions for common SSH tasks

## Usage Examples

After running the one-liner above, you'll have several capabilities:

### Basic SSH

```python
# Connect to a server
!ssh username@hostname

# Copy files to a server
!scp localfile.txt username@hostname:/path/

# Copy files from a server
!scp username@hostname:/path/file.txt ./
```

### Git with SSH

```python
# Clone a private repository
!git clone git@github.com:username/repo.git
```

### SSHX Tunneling

```python
# Create a new tunnel
!~/bin/sshx create --name my-tunnel

# Connect to a tunnel
!~/bin/sshx connect my-tunnel

# Allow reverse connections to your notebook
!~/bin/sshx serve --port 8022
```

## Security Notes

- The generated SSH key has no passphrase for automation purposes
- SSH StrictHostKeyChecking is disabled by default for ease of use
- Consider adjusting these settings for production use