# 🔍 Packet Analyzer

Packet Analyzer is a Python and Flask-based project that helps monitor and analyze network traffic. The main idea behind this project is to make packet analysis easier to understand by capturing network packets, identifying protocols, detecting suspicious activity, and displaying useful information through a web dashboard.

## 💡 Why I Built This

While learning about computer networks and cybersecurity, I wanted to build something practical instead of only studying packet capture and protocols theoretically.

This project helped me understand how network packets move through a system and how tools can be used to identify unusual or suspicious traffic.

## ✨ What It Can Do

- Capture and analyze network packets
- Identify different network protocols
- Monitor network traffic
- Detect potentially suspicious activity
- Generate alerts for detected threats
- Display packet and threat information through a dashboard
- Provide user login and registration
- Analyze PCAP files
- Generate test traffic for experimenting with threat detection

## 🛠️ Technologies Used

- Python
- Flask
- Scapy
- HTML
- CSS
- JavaScript
- SQLite
- SQLAlchemy
- Werkzeug

## 📂 Project Structure

```text
packet-analyzer/
│
├── app.py
├── auth.py
├── detector.py
├── models.py
├── sniffer.py
├── alerts.js
├── test_app.py
├── requirements.txt
│
├── static/
│   ├── script.js
│   └── style.css
│
└── templates/
    ├── dashboard.html
    ├── login.html
    └── register.html
