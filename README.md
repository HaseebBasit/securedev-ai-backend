# SecureDev AI — Backend API

High-performance, secure Node.js + Express REST API designed for **SecureDev AI** (IBM Bob 2.0 Hackathon on LabLab.ai).

## Features

- **Evidence-Based Security Engine**: AI abstraction layer (`aiService`) supporting IBM Bob / WatsonX / Gemini / OpenAI-compatible models, with a built-in zero-config heuristic fallback analyzer for $0 budget / offline execution.
- **Deterministic Security Scoring**: 0–100 score calculation based on strict severity penalties (Critical: -30, High: -20, Medium: -10, Low: -5).
- **Safe Architecture**:
  - Zero-Execution Principle: Submitted source code is never executed, compiled, or evaluated.
  - Zero-Leakage: User code is never permanently stored in the database.
  - Rate limiting (Express Rate Limit), security headers (Helmet), and strict CORS.
  - Safe logger masking secrets, API keys, and MongoDB URIs from logs.
- **Database Resilience**: Connects to MongoDB Atlas Free Tier (`securedev_ai` database). If MongoDB is offline or unconfigured, gracefully switches to stateless in-memory mode without breaking analysis.

## Project Structure

```
backend/
├── config/
│   └── database.js               # MongoDB Atlas connection & health reporting
├── controllers/
│   └── analysisController.js     # Health, analyze, history, and stats controllers
├── middleware/
│   ├── errorMiddleware.js        # Safe error masking & 404 handler
│   ├── rateLimitMiddleware.js    # Per-IP rate limiting
│   └── validationMiddleware.js   # Code length, language & payload validation
├── models/
│   └── Analysis.js               # Mongoose schema for analysis metadata
├── routes/
│   └── analysisRoutes.js         # REST route declarations
├── services/
│   ├── aiService.js              # AI provider abstraction & heuristic engine
│   └── scoringService.js         # Deterministic scoring formula
├── utils/
│   ├── safeLogger.js             # Credential & code leak prevention logger
│   └── validators.js             # Language taxonomy & limits
├── .env.example                  # Environment configuration template
├── package.json
└── server.js                     # Application entry point
```

## Quick Start

### 1. Install Dependencies
```bash
cd backend
npm install
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Fill in `.env`:
```ini
PORT=5000
CLIENT_URL=http://localhost:3000
MONGODB_URI=mongodb+srv://<username>:<password>@cluster0.mongodb.net/securedev_ai?retryWrites=true&w=majority
AI_PROVIDER=heuristic
AI_API_KEY=
AI_MODEL=ibm-bob-appsec
```
*(Note: If `MONGODB_URI` is blank, the server automatically boots in stateless in-memory mode).*

### 3. Run Backend
```bash
npm start
```
Dev mode with auto-reload:
```bash
npm run dev
```

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service health, uptime, and database connection status |
| `POST` | `/api/analyze` | Analyzes code for security vulnerabilities |
| `GET` | `/api/analyses` | Retrieves recent analysis history metadata |
| `GET` | `/api/analyses/:id` | Retrieves single analysis report by ID |
| `GET` | `/api/stats` | Aggregate dashboard statistics (scores, risk counts) |
