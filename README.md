# SpyNet - Network Traffic Analyzer and Intrusion Detection System

SpyNet is an advanced Network Traffic Analyzer and Intrusion Detection System (IDS) designed to provide real-time network monitoring, threat detection, and security analysis.

## Project Structure

```
SpyNet/
├── backend/          # Python FastAPI backend with packet capture and analysis
├── frontend/         # Next.js dashboard with TypeScript and Tailwind CSS
├── .kiro/           # Kiro IDE specifications and configuration
└── README.md        # This file
```

## Getting Started

### Backend Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

## Features

- Real-time packet capture and analysis
- Advanced threat detection engine
- Machine learning-based anomaly detection
- Interactive dashboard and visualization
- Comprehensive alerting system
- Advanced reporting and forensics