# SpyNet Dashboard

A modern, responsive web dashboard for the SpyNet Network Traffic Analyzer and Intrusion Detection System.

## Features

### 🎨 Modern UI/UX
- **Responsive Design**: Mobile-friendly interface built with Tailwind CSS
- **Dark/Light Mode**: Toggle between themes with system preference detection
- **Real-time Updates**: Live data streaming via WebSocket connections
- **Interactive Charts**: Traffic visualization using Recharts library

### 📊 Dashboard Components
- **Statistics Cards**: Real-time network metrics (packets, bytes, connections, alerts)
- **Traffic Chart**: Live network traffic visualization with dual-axis charts
- **Top Talkers**: Most active IP addresses with bandwidth usage
- **Alerts Table**: Interactive security alerts with filtering and sorting

### 🔍 Alert Management
- **Advanced Filtering**: Filter alerts by severity level
- **Search Functionality**: Search across alert types, IPs, and descriptions
- **Sorting**: Sort by timestamp, severity, type, or source IP
- **Severity Indicators**: Color-coded severity levels (Low, Medium, High, Critical)

### 🔌 Real-time Connectivity
- **WebSocket Integration**: Live data updates from SpyNet backend
- **Connection Status**: Visual indicator of backend connectivity
- **Mock Data**: Development mode with simulated data when backend is unavailable

## Getting Started

### Prerequisites
- Node.js 18+ 
- npm or yarn

### Installation

1. Install dependencies:
```bash
npm install --legacy-peer-deps
```

2. Start the development server:
```bash
npm run dev
```

3. Open [http://localhost:3000](http://localhost:3000) in your browser

### Production Build

```bash
npm run build
npm start
```

## Architecture

### Components Structure
```
src/
├── app/
│   └── page.tsx              # Main dashboard page
├── components/
│   ├── AlertsTable.tsx       # Interactive alerts table
│   ├── StatsCards.tsx        # Network statistics cards
│   ├── TopTalkers.tsx        # Top bandwidth users
│   └── TrafficChart.tsx      # Real-time traffic chart
└── hooks/
    ├── useTheme.ts           # Theme management
    └── useWebSocket.ts       # WebSocket connection
```

### Key Technologies
- **Next.js 15**: React framework with App Router
- **TypeScript**: Type-safe development
- **Tailwind CSS**: Utility-first styling
- **Recharts**: Chart library for data visualization
- **Socket.io Client**: Real-time WebSocket communication
- **Lucide React**: Modern icon library

## WebSocket API

The dashboard connects to the SpyNet backend via WebSocket at `ws://localhost:8000/ws` and listens for:

- `traffic_update`: Real-time traffic data
- `new_alert`: Security alert notifications  
- `stats_update`: Network statistics updates
- `top_talkers_update`: Bandwidth usage rankings

## Development Features

- **Mock Data**: Automatic fallback to simulated data when backend is unavailable
- **Hot Reload**: Instant updates during development
- **TypeScript**: Full type safety and IntelliSense
- **ESLint**: Code quality and consistency

## Responsive Design

The dashboard is fully responsive and optimized for:
- **Desktop**: Full-featured dashboard layout
- **Tablet**: Adaptive grid layouts
- **Mobile**: Stacked components with touch-friendly controls
