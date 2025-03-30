# SSH Access for Jupyter Notebooks

This repository provides a one-line solution for setting up SSH access in Jupyter notebooks and other restricted environments, with special support for terminal access and Python 3.6+ compatibility.

## One-Line Solution

Copy and paste this single line into your Jupyter notebook cell to set up complete SSH access:

```python
!python3 -c "import urllib.request; exec(urllib.request.urlopen('https://raw.githubusercontent.com/malc3om/ssh-access/main/notebook_ssh.py').read().decode())"
```

## What This Does

This solution will:

1. Generate SSH keys automatically
2. Set up proper SSH configuration
3. Create terminal access scripts
4. Set up Git with your SSH key
5. Create SSH tunneling capabilities
6. Provide detailed instructions

## Key Features

- **Python 3.6+ Compatible**: Works with older Python versions
- **No External Dependencies**: Uses only standard library modules
- **Terminal Access**: Creates scripts for direct terminal access
- **Multiple Terminal Methods**: Tries several methods to provide terminal access
- **SSH Tunneling**: Pure Python implementation of SSH tunneling
- **No sudo Required**: Works without elevated privileges
- **Git Integration**: Configures Git to use your SSH keys

## Getting a Terminal

After running the one-liner, you'll get a script you can run:

```python
# Start a terminal service
!python3 ~/start_terminal.py
```

This will:
1. Try multiple terminal services (ttyd, shellinabox, sshd)
2. If available, start a web-based or SSH terminal
3. If not, provide a Python-based fallback terminal

## SSH Commands

```python
# Connect to a server
!ssh username@hostname

# Copy files to a server
!scp localfile.txt username@hostname:/path/

# Copy files from a server
!scp username@hostname:/path/file.txt ./
```

## Git with SSH

```python
# Clone a private repository
!git clone git@github.com:username/repo.git

# Clone with explicit key specification
!GIT_SSH_COMMAND="ssh -i ~/.ssh/id_rsa" git clone git@github.com:username/repo.git
```

## SSH Tunneling

```python
# Create a tunnel forwarding local port 8080 to example.com:80
!python3 ~/ssh_tunnel.py 8080 example.com 80
```

## Security Notes

- SSH keys are generated without a passphrase for automation
- StrictHostKeyChecking is disabled by default
- Consider enhancing security for production use