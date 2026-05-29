import os
import json
import socket
import requests

SERVER_URL = "http://127.0.0.1:8000/api/scan"


def extract_npm_packages(file_path: str) -> list:
    packages = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            all_dependencies = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for name, version in all_dependencies.items():
                packages.append({
                    "name": name,
                    "version": version.lstrip("^~<>="),
                    "ecosystem": "npm"
                })
    except Exception as e:
        print(f"[-] Error reading {file_path}: {e}")
    return packages


def scan_directory(target_dir: str) -> list:
    found_packages = []

    try:
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d.lower() not in [
                "node_modules", ".venv", "venv", ".git", "__pycache__",
                "windows", "program files", "program files (x86)", "$recycle.bin"
            ]]

            for file in files:
                if file == "package.json":
                    full_path = os.path.join(root, file)
                    print(f"[+] Found config: {full_path}")
                    found_packages.extend(extract_npm_packages(full_path))
    except PermissionError:
        pass
    except Exception as e:
        print(f"[-] Scan error in {target_dir}: {e}")

    return found_packages


def run_agent():
    print("====================================")
    print("    WELCOME TO PKGSCAN AGENT v2.0   ")
    print("====================================")
    print("Choose your Scan Mode:")
    print("1. Basic Scan    (Fast - Scans Desktop & Documents)")
    print("2. Advanced Scan (Thorough - Scans whole system, takes time)")
    print("3. Custom Scan   (Targeted - You choose the path)")
    print("------------------------------------")

    choice = input("Enter choice (1/2/3): ").strip()

    paths_to_scan = []
    user_home = os.path.expanduser("~")

    if choice == "1":
        print("[*] Setting up Basic Scan...")
        paths_to_scan = [
            os.path.join(user_home, "Desktop"),
            os.path.join(user_home, "Documents")
        ]
    elif choice == "2":
        print("[*] Setting up Advanced Scan (Whole System)...")
        paths_to_scan = ["C:\\"] if os.name == "nt" else ["/"]
    elif choice == "3":
        custom_path = input("Enter the absolute path to scan: ").strip()
        if os.path.exists(custom_path):
            paths_to_scan = [custom_path]
        else:
            print("[❌] Error: Path does not exist!")
            return
    else:
        print("[❌] Invalid choice. Exiting.")
        return

    all_discovered_packages = []
    for path in paths_to_scan:
        print(f"[*] Scanning path: {path}")
        all_discovered_packages.extend(scan_directory(path))

    unique_packages = [dict(t) for t in {tuple(d.items()) for d in all_discovered_packages}]

    hostname = socket.gethostname()
    endpoint_id = f"{hostname}-Agent"

    print(f"\n[+] Local scan finished. Found {len(unique_packages)} unique packages.")
    print("[*] Sending data to server for vulnerability analysis...")

    send_to_server(endpoint_id, unique_packages)


def send_to_server(endpoint_id: str, packages: list):
    if not packages:
        print("[-] No packages to report.")
        return

    payload = {"endpoint_id": endpoint_id, "packages": packages}
    num_packages = len(packages)
    dynamic_timeout = 5 + (num_packages * 0.5)

    try:
        response = requests.post(SERVER_URL, json=payload, timeout=dynamic_timeout)

        if response.status_code == 200:
            server_data = response.json()

            vulnerable_count = sum(1 for res in server_data.get("results", []) if res["status"] == "VULNERABLE")

            print("\n=========================================")
            print("✅ Scan Completed Successfully!")
            print(f"📊 Summary: Scanned {num_packages} packages, Found {vulnerable_count} vulnerabilities.")
            print("=========================================")
            print(f"🔍 Your Endpoint ID is: {endpoint_id}")
            print("👉 To view the full security report, go to your PkgScan Dashboard:")
            print("   http://localhost:5173")
            print("=========================================\n")

        else:
            print(f"[-] Server error {response.status_code}: {response.text}")
    except requests.exceptions.Timeout:
        print(f"[❌] Timeout Error: Server took longer than {dynamic_timeout} seconds to respond.")
    except Exception as e:
        print(f"[-] Connection error: {e}")

if __name__ == "__main__":
    run_agent()