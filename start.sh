#!/bin/bash

cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    echo "[!] Virtual environment not found."
    echo "Run: python3 -m venv venv"
    exit 1
fi

source venv/bin/activate
python3 SentinelSOC_Pro.py
