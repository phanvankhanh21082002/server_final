#!/bin/bash

# Update package lists
sudo apt-get update
sudo apt-get install -y apache2
sudo mkdir -p /var/www/html/reports_html
sudo mkdir -p /var/www/html/reports_txt

sudo apt-get install -y unzip wget

# Install ClamAV
sudo apt-get install -y clamav clamav-daemon

# Update ClamAV virus definitions
sudo freshclam

# Install Python and pip if not already installed
sudo apt-get install -y python3 python3-pip
sudo apt-get install inotify-tools=3.22.6.0-4

# Install Python packages
pip3 install pyyaml==6.0.1 androguard==3.3.5 apkid==2.1.5 yara-python==3.11.0 apkutils==1.5.3
pip3 install numpy==1.26.4 tensorflow==2.17.0 pillow==10.4.0 lief==0.14.1 requests==2.28.1 phonenumbers==8.13.40

curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
sudo apt-get install -y nodejs

# Navigate to the server directory
cd ../server

# Install necessary Node.js packages
npm install express express-fileupload

echo "All tools have been installed successfully."
