# 🕵️ SpyNet: Advanced Network Security & Intrusion Detection

<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Next.js-000000?style=for-the-badge&logo=nextdotjs&logoColor=white" alt="Next.js">
  <img src="https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/Scapy-FF6B6B?style=for-the-badge&logo=python&logoColor=white" alt="Scapy">
</p>

**SpyNet** is a comprehensive Network Traffic Analyzer and Intrusion Detection System (IDS) that provides real-time network monitoring, advanced threat detection, and forensic analysis capabilities.

![Project Image](https://1f7v31ruea.ufs.sh/f/iyuvgiGeX9G2U7p5DAtdTGCWJiH37lEZLrsh1OSP4bwjRDf9)

## 🛠️ Tech Stack

<table>
<tr>
  <td><b>🎨 Frontend</b></td>
  <td>Next.js, React, TypeScript, Tailwind CSS, Recharts</td>
</tr>
<tr>
  <td><b>⚡ Backend</b></td>
  <td>Python, FastAPI, Scapy, SQLAlchemy</td>
</tr>
<tr>
  <td><b>💾 Database</b></td>
  <td>PostgreSQL, NeonDB</td>
</tr>
<tr>
  <td><b>🔍 Analysis</b></td>
  <td>Scikit-learn, Pandas, Machine Learning</td>
</tr>
<tr>
  <td><b>📡 Real-time</b></td>
  <td>WebSockets, REST API</td>
</tr>
</table>

---

## ✨ Features

<ul>
<li>📡 <b>Real-Time Packet Capture</b> - Live network traffic monitoring and analysis</li>
<li>🛡️ <b>Intrusion Detection</b> - Advanced threat detection with ML-based anomaly detection</li>
<li>📊 <b>Interactive Dashboard</b> - Beautiful real-time web interface with live charts</li>
<li>🔍 <b>Forensic Analysis</b> - Advanced search and filtering across network data</li>
<li>📈 <b>Comprehensive Reporting</b> - Security summaries, trend analysis, compliance reports</li>
<li>🚨 <b>Smart Alerting</b> - Intelligent alert system with severity classification</li>
<li>⚡ <b>High Performance</b> - Optimized packet processing and database queries</li>
<li>🔧 <b>CLI Tools</b> - Command-line interface for automation and scripting</li>
</ul>

---

## 🏗️ Architecture

### System Overview
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Web Dashboard  │    │   CLI Tools     │    │  REST API       │
│  (Next.js)      │    │   (Python)      │    │  (FastAPI)      │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
          ┌────────────────────────▼────────────────────────┐
          │              SpyNet Core Engine                 │
          │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ 
          │  │   Packet    │  │   Threat    │  │  Anomaly    │ 
          │  │  Capture    │  │  Detection  │  │  Detection  │ 
          │  └─────────────┘  └─────────────┘  └─────────────┘ 
          └────────────────────────┬────────────────────────┘
                                   │
          ┌────────────────────────▼────────────────────────┐
          │              PostgreSQL Database                │
          │  • Packet Data    • Security Alerts             │
          │  • Connections    • System Configuration        │
          │  • Forensic Logs  • Historical Analytics        │
          └─────────────────────────────────────────────────┘

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.8+**
- **Node.js 16+** and **npm**
- **PostgreSQL** (local or NeonDB)
- **Administrator privileges** (for packet capture)

### One-Command Setup

**1. Clone and Setup Backend:**
```bash
git clone <repository-url>
cd SpyNet/backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Setup environment
cp .env.example .env
# Edit .env with your database URL

# Initialize database
python init_database.py
```

**2. Setup Frontend:**
```bash
cd ../frontend
npm install
cp .env.local.example .env.local
```

**3. Start Services:**
```bash
# Terminal 1 - Backend
cd backend
venv\Scripts\activate  # Windows
python main.py

# Terminal 2 - Frontend
cd frontend
npm run dev
```

**4. Access Dashboard:**
```
Frontend: http://localhost:3000
API Docs: http://localhost:8000/docs
```

---

## 🤖 Machine Learning & AI Engine

### Isolation Forest Anomaly Detection

**SpyNet employs advanced machine learning for intelligent threat detection:**

#### **Core ML Algorithm**
- **Model**: Scikit-learn Isolation Forest (100 estimators)
- **Type**: Unsupervised anomaly detection
- **Purpose**: Zero-day attack detection and behavioral analysis
- **Training**: Adaptive baseline learning from normal traffic

---

## 🔍 Security Detection Capabilities

### Machine Learning & AI Detection

**SpyNet uses advanced machine learning algorithms for intelligent threat detection:**

#### 🤖 **Isolation Forest Algorithm**
- **Model**: Scikit-learn Isolation Forest with 100 estimators
- **Purpose**: Unsupervised anomaly detection for zero-day attacks
- **Features**: 15+ network traffic features including packet size, protocol patterns, timing analysis
- **Training**: Adaptive baseline learning from normal traffic patterns
- **Performance**: Real-time scoring with configurable contamination thresholds

#### 📊 **Feature Engineering**
```python
# Extracted Features for ML Analysis:
- Packet size and payload analysis
- Protocol distribution patterns  
- Port access patterns and frequency
- Temporal features (time of day, weekend detection)
- Traffic flow characteristics (packets/sec, bytes/sec)
- TCP flag combinations and sequences
- Source/destination IP behavior patterns
```

#### 🔄 **Adaptive Learning**
- **Baseline Training*Critical** as learning from network patterns
- **Model Updates**: Automatic retraining with new traffic data
- **False Positive Reduction**: Statistical baseline comparison
- **Contamination Tunong**: Configurmalymaly detection sensitivity

---

## 📊 Dashboard Features

### Real-Time Monitoring
- **Live traffic charts** with packet and byte counts
- **Security alert feed** with severity classification
- **Top talkers** showing most active IP addresses
- **Protocol distribution** pie charts and statistics
- **Connection status** and active session tracking

### Reporting Interface
- **Security summaries** with risk scoring
- **Trend analysis** with historical comparisons
- **Compliance reports** for audit requirements
- **Data export** in multiple formats
- **Custom date ranges** and filtering options

---

## 🛡️ Security Features

### Data Protection
- **Encrypted database** connections
- **Secure API** endpoints with authentication
- **Input validation** and sanitization
- **SQL injection** protection
- **XSS prevention** in web interface

### Network Security
- **Passive monitoring** - no network disruption
- **Isolated analysis** environment
- **Configurable interfaces** for monitoring
- **Safe packet capture** with proper permissions

---

## 🤝 Contributing

<ul>
<li>🐛 <b>Report Issues</b> - Found a bug? Let us know!</li>
<li>💡 <b>Feature Requests</b> - Ideas for improvements?</li>
<li>🔧 <b>Pull Requests</b> - Code contributions welcome</li>
<li>📖 <b>Documentation</b> - Help improve our docs</li>
<li>⭐ <b>Star the Repo</b> - Show your support!</li>
</ul>

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

