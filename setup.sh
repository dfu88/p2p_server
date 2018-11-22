#!/bin/bash

clear

echo "P2P Client Setup"
echo "Setting up Python virtual environment..."

virtualenv -p /usr/bin/python2.7 venv
source venv/bin/activate

echo "Installing packages using pip..."
pip install CherryPy==3.7.0
pip install pycrypto
pip install bcrypt
pip install scrypt
pip install passlib
pip install pyotp