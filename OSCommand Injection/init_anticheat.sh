#!/bin/bash

# Simple anti-cheat initialization
# Clean up any existing flags and create secure directories

echo "🔒 Initializing anti-cheat system..."

# Ensure /var/flags is clean to prevent cheating
rm -rf /var/flags/* 2>/dev/null
mkdir -p /var/flags
chmod 755 /var/flags

# Create /tmp directory if not exists
mkdir -p /tmp
chmod 777 /tmp

# Clean any existing flag files
rm -f /tmp/level*_flag.txt 2>/dev/null
rm -f /var/www/html/level*_flag.txt 2>/dev/null

echo "✅ Anti-cheat system initialized"
echo "📍 Real flags will be generated in /tmp/levelX_flag.txt when accessing each level"
echo "🚫 /var/flags directory is kept clean to prevent cross-level access"
