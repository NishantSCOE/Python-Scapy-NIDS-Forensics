# 🛡️ Python-Scapy-NIDS-Forensics: Custom Network IDS and Packet Sniffer

## Project Overview
This project implements a lightweight, custom **Network Intrusion Detection System (NIDS)** and packet analyzer using **Python 3**. Developed as a foundational tool for network monitoring and **Digital Forensics**, it demonstrates the ability to interact directly with the network stack using **Scapy** to process, log, and analyze live traffic for anomalous behavior.

The system is designed for use in a controlled lab environment (such as Kali Linux) and showcases core skills relevant to ethical hacking, network analysis, and incident response.

## ✨ Key Features

* **Real-time Packet Capture:** Sniffs and parses live network traffic on a specified interface using the powerful **Scapy** library.
* **Anomaly Detection (IDS Logic):**
    * **Port Scan Detection:** Alerts when a single source IP targets more than 10 unique destination ports in a short time.
    * **Flood Attack Detection:** Alerts when a source IP sends over 100 packets within a 10-second window.
* **Data Persistence & Forensics:**
    * Logs all packet metadata to a flat file (`packet_log.txt`) for quick review.
    * Stores all records in a structured **SQLite database** (`packets.db`) for efficient querying and post-incident analysis.
* **Live Reporting:** Prints a continuous, aggregate traffic summary, including **Protocol Breakdown (TCP, UDP, ICMP)** and **Top 5 Source/Destination IPs**, queried directly from the database.
* **Concurrency:** Utilizes Python's `threading` and `multiprocessing` to ensure non-blocking packet processing and live visualization (optional).

## 🛠️ Technologies Used

| Category | Tool | Purpose |
| :--- | :--- | :--- |
| **Language** | Python 3.x | Core programming language. |
| **Sniffing** | Scapy | Packet construction, injection, and analysis. |
| **Database** | SQLite3 | Local, persistent database for forensic data logging. |
| **Visualization** | Matplotlib (Optional) | Live graphical representation of traffic volume. |

## 🚀 Installation and Usage

### 1. Prerequisites
* A Linux environment (Kali/Ubuntu/etc.) is highly recommended.
* **Root/sudo privileges** are required to run the packet capture process.

### 2. Setup Steps
1.  **Clone the Repository** and navigate into the folder.
2.  **Create and Activate Virtual Environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # For Linux/macOS
    # .\venv\Scripts\Activate.ps1  # For Windows PowerShell
    ```
3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

### 3. Execution (Requires Sudo/Root)

Run the main script. Replace `[INTERFACE]` with your actual network interface (e.g., `eth0`, `wlan0`, etc.).

```bash
sudo python3 sniffer.py --interface [INTERFACE] --summary-interval 10 --show-graph