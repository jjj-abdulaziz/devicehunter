# 🕵️ DeviceHunter

**DeviceHunter** is a network and device reconnaissance tool built in Python for discovering devices on a local network, detecting nearby Bluetooth/BLE devices, fingerprinting exposed services, and identifying potential vulnerabilities through the **NVD CVE database**.

It brings several reconnaissance and vulnerability-assessment tasks into a single command-line tool.

> ⚠️ **Important:** DeviceHunter is intended for authorized security testing, cybersecurity education, and network administration. Only scan networks, devices, and systems that you own or have explicit permission to test.

---

## ✨ Features

### 🌐 Network Discovery

Discover devices connected to a local network using:

* ARP-based host discovery
* Ping-based fallback discovery
* Automatic local subnet detection
* Explicit subnet targeting

Example:

```bash
sudo devicehunter network
```

Specify a subnet manually:

```bash
sudo devicehunter network --subnet 192.168.1.0/24
```

---

### 🔎 Service Fingerprinting

After discovering hosts, DeviceHunter can use **Nmap service detection** to identify:

* Open ports
* Running services
* Service versions
* Product information

The discovered service and version information can then be used for vulnerability analysis.

Example:

```bash
sudo devicehunter network
```

For a more comprehensive port scan:

```bash
sudo devicehunter network --subnet 192.168.1.0/24 --full
```

---

### 📡 Bluetooth & BLE Discovery

DeviceHunter can discover nearby Bluetooth and Bluetooth Low Energy devices.

BLE scanning is handled through `bleak`, while classic Bluetooth discovery on Linux uses `bluetoothctl` and BlueZ.

Example:

```bash
sudo devicehunter bluetooth --timeout 15
```

---

### 🛡️ CVE Vulnerability Lookup

DeviceHunter can check discovered software and service versions against the **National Vulnerability Database (NVD)**.

The vulnerability lookup can return information such as:

* CVE ID
* CVSS severity
* CVSS score
* Vulnerability summary
* Matching product/version information

The tool uses the NVD CVE 2.0 API and includes caching and throttling to reduce unnecessary requests.

> **Note:** CVE matching is not proof that a system is vulnerable. Results should always be manually verified.

---

### 📄 JSON Reports

Results can be exported to a JSON file for later analysis, documentation, or integration with other security tools.

```bash
sudo devicehunter all --json report.json
```

---

## 🧰 Technology Stack

DeviceHunter is built with:

| Technology | Purpose                                  |
| ---------- | ---------------------------------------- |
| Python     | Core application                         |
| Scapy      | Network discovery and ARP scanning       |
| Nmap       | Port scanning and service fingerprinting |
| Bleak      | Bluetooth/BLE scanning                   |
| BlueZ      | Classic Bluetooth discovery on Linux     |
| Requests   | NVD API communication                    |
| Rich       | Terminal output and formatting           |
| NVD API    | CVE vulnerability information            |

---

## 📋 Requirements

### Software

* Python **3.9+**
* Nmap
* BlueZ for classic Bluetooth scanning on Linux

The Python dependencies are listed in `requirements.txt`:

```text
scapy>=2.5.0
python-nmap>=0.7.1
bleak>=0.21.1
requests>=2.31.0
rich>=13.7.0
```

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/jjj-abdulaziz/devicehunter.git
cd devicehunter
```

### 2. Install system dependencies

On Debian-based Linux distributions such as Kali Linux or Ubuntu:

```bash
sudo apt update
sudo apt install nmap bluez
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Install DeviceHunter

Install the project in editable mode:

```bash
pip install -e .
```

You should then be able to run:

```bash
devicehunter
```

---

## 💻 Usage

DeviceHunter provides several scanning modes.

### Network Scan

Discover local network hosts, fingerprint their services, and perform vulnerability lookups:

```bash
sudo devicehunter network
```

---

### Network Scan With a Specific Subnet

```bash
sudo devicehunter network --subnet 192.168.1.0/24
```

---

### Full Port Scan

```bash
sudo devicehunter network --subnet 192.168.1.0/24 --full
```

---

### Network Scan Without Vulnerability Checks

If you only want discovery and service fingerprinting:

```bash
sudo devicehunter network --subnet 192.168.1.0/24 --full --no-vulns
```

This can be useful when you want to reduce API requests or perform reconnaissance without CVE lookups.

---

### Bluetooth Scan

Scan for nearby Bluetooth/BLE devices:

```bash
sudo devicehunter bluetooth --timeout 15
```

You can adjust the timeout:

```bash
sudo devicehunter bluetooth --timeout 30
```

---

### Scan Everything

Run both network and Bluetooth discovery:

```bash
sudo devicehunter all
```

Save the results as JSON:

```bash
sudo devicehunter all --json report.json
```

---

## 🔐 Why `sudo`?

Some network discovery techniques require access to raw network sockets.

For example, ARP scanning through Scapy generally requires elevated privileges.

Therefore, most DeviceHunter commands should be run with:

```bash
sudo
```

If you run without sufficient privileges, some discovery methods may fail or automatically fall back to less privileged techniques.

---

## ⚙️ How DeviceHunter Works

The general workflow is:

```text
                 ┌──────────────────┐
                 │   DeviceHunter   │
                 └────────┬─────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
      ┌───────────────┐       ┌──────────────┐
      │ Network Scan  │       │ Bluetooth/BLE│
      └───────┬───────┘       └──────┬───────┘
              │                      │
              ▼                      ▼
      ┌───────────────┐       ┌──────────────┐
      │ Host Discovery│       │ Device       │
      │ ARP / Ping    │       │ Discovery    │
      └───────┬───────┘       └──────────────┘
              │
              ▼
      ┌───────────────┐
      │ Nmap Service  │
      │ Fingerprinting│
      └───────┬───────┘
              │
              ▼
      ┌───────────────┐
      │ Product /     │
      │ Version Data  │
      └───────┬───────┘
              │
              ▼
      ┌───────────────┐
      │ NVD CVE       │
      │ Lookup        │
      └───────┬───────┘
              │
              ▼
      ┌───────────────┐
      │ Results /     │
      │ JSON Report   │
      └───────────────┘
```

### Network Discovery

DeviceHunter first attempts to discover hosts on the local network using an ARP sweep through Scapy.

If Scapy or the required privileges are unavailable, it can fall back to a ping-based discovery method.

### Service Fingerprinting

Discovered hosts can then be examined using Nmap's service detection capabilities:

```bash
nmap -sV
```

This attempts to identify the services, products, and versions running on accessible ports.

### Vulnerability Analysis

The identified software and versions are passed to the NVD CVE API.

DeviceHunter attempts to match the discovered products against known vulnerabilities and returns relevant CVE information.

---

## 📁 Project Structure

The project is organized as a Python package with the main `devicehunter` module, installation configuration, and dependency files.

```text
devicehunter/
├── devicehunter/
│   ├── ...
│
├── requirements.txt
├── setup.py
├── .gitignore
├── gitignore
└── README.md
```

The package exposes the following command:

```text
devicehunter
```

through the project's console entry point.

---

## ⚠️ Limitations

DeviceHunter is designed to assist with reconnaissance and vulnerability assessment, but its results should not be treated as definitive security findings.

### CVE Detection

NVD keyword matching can produce approximate matches.

A reported CVE should therefore be manually verified before being considered a confirmed vulnerability.

### Bluetooth

Classic Bluetooth discovery depends on:

```text
BlueZ
bluetoothctl
```

and is therefore primarily supported on Linux.

BLE scanning through `bleak` provides broader platform support.

### NVD Rate Limits

Unauthenticated requests to the NVD API are rate-limited.

For heavier use, an NVD API key can be configured to increase the available request rate.

---

## 🔒 Responsible Use

DeviceHunter can perform network and device discovery. Because of this, it should only be used in environments where you have authorization.

### ✅ Appropriate Uses

* Your own home network
* Your own devices
* Authorized penetration tests
* Cybersecurity labs
* CTF environments
* University security projects
* Security research with permission
* Network administration

### ❌ Do Not Use Against

* Networks you do not own
* Public Wi-Fi without permission
* Other people's devices
* Corporate networks without authorization
* Infrastructure belonging to third parties

Unauthorized scanning may violate organizational policies or applicable laws.

---

## 🧪 Example Workflow

A basic authorized assessment could look like this:

### Step 1: Discover devices

```bash
sudo devicehunter network
```

### Step 2: Perform a more comprehensive scan

```bash
sudo devicehunter network --subnet 192.168.1.0/24 --full
```

### Step 3: Scan nearby Bluetooth devices

```bash
sudo devicehunter bluetooth --timeout 15
```

### Step 4: Generate a report

```bash
sudo devicehunter all --json report.json
```

The resulting JSON file can then be used for further analysis or documentation.

---

## 🛣️ Roadmap

Potential future improvements include:

* [ ] Improved device identification
* [ ] Better OS fingerprinting
* [ ] MAC vendor identification
* [ ] More accurate CPE matching
* [ ] Improved CVE correlation
* [ ] HTML report generation
* [ ] CSV export
* [ ] Configurable scan profiles
* [ ] Scan history
* [ ] Additional Bluetooth information
* [ ] Improved error handling
* [ ] Unit and integration tests
* [ ] Optional NVD API key configuration
* [ ] More cross-platform support

---

## 🤝 Contributing

Contributions, bug reports, feature requests, and improvements are welcome.

### Fork the repository

```bash
git clone https://github.com/jjj-abdulaziz/devicehunter.git
cd devicehunter
```

Create a branch:

```bash
git checkout -b feature/my-feature
```

Make your changes, test them, then commit:

```bash
git add .
git commit -m "Add my feature"
```

Push your branch:

```bash
git push origin feature/my-feature
```

Then open a pull request.

---

## 📜 License

See the repository for the current licensing information.

---

## 👨‍💻 Author

**Abdulaziz**

GitHub:

[@jjj-abdulaziz](https://github.com/jjj-abdulaziz?utm_source=chatgpt.com)

Project:

[DeviceHunter](https://github.com/jjj-abdulaziz/devicehunter?utm_source=chatgpt.com)

---

## ⭐ Support

If you find DeviceHunter useful, consider giving the repository a ⭐ on GitHub.

Feedback, issues, and suggestions are welcome.

---

### ⚠️ Disclaimer

DeviceHunter is provided for educational, defensive security, and authorized testing purposes.

The developer is not responsible for misuse of the software or for scanning systems without appropriate authorization.
