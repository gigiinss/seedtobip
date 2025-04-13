#!/bin/bash

# Ensure the .ssh directory exists
mkdir -p ~/.ssh
chmod 700 ~/.ssh

# Generate SSH key with ed25519
ssh-keygen -t ed25519 -C "your_email@example.com"

# Start SSH agent
eval "$(ssh-agent -s)"

# Add SSH key to agent
ssh-add ~/.ssh/id_ed25519

# For Linux, use xclip to copy to clipboard (install first if needed)
# Uncomment and install xclip if you want automatic clipboard copying
# sudo apt-get install xclip
# xclip -sel clip < ~/.ssh/id_ed25519.pub

# Display the public key (you can manually copy this)
echo "SSH Public Key:"
cat ~/.ssh/id_ed25519.pub

# Verify SSH connection to GitHub
ssh -T git@github.com
