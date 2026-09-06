require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { connectDB } = require('./config/database');
const analysisRoutes = require('./routes/analysisRoutes');
const { apiLimiter } = require('./middleware/rateLimitMiddleware');
const { errorHandler, notFoundHandler } = require('./middleware/errorMiddleware');
const safeLogger = require('./utils/safeLogger');

const app = express();
const PORT = process.env.PORT || 5000;
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:3000';

// 1. Security Headers
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// 2. CORS Configuration - Permissive for Vercel, localhost, and custom domains
app.use(cors({
  origin: true, // Dynamically reflects origin and allows credentials
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// 3. Body Parsers with size limits
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true, limit: '256kb' }));

// 4. Rate Limiter on API namespace
app.use('/api', apiLimiter);

// 5. Mount API Routes
app.use('/api', analysisRoutes);

// Root route
app.get('/', (req, res) => {
  res.json({
    name: 'SecureDev AI API',
    tagline: 'Your AI Security Partner for Development',
    status: 'online',
    documentation: '/api/health',
    version: '1.0.0'
  });
});

// 6. 404 & Global Error Handling
app.use(notFoundHandler);
app.use(errorHandler);

// 7. Start Server & Connect to DB
const startServer = async () => {
  // Connect to MongoDB Atlas (resilient, non-blocking if offline)
  await connectDB();

  const server = app.listen(PORT, () => {
    safeLogger.info(`SecureDev AI Backend listening on port ${PORT}`);
    safeLogger.info(`Health check available at: http://localhost:${PORT}/api/health`);
  });

  // Graceful shutdown
  const shutdown = () => {
    safeLogger.info('Received kill signal, shutting down gracefully...');
    server.close(() => {
      safeLogger.info('Closed out remaining connections.');
      process.exit(0);
    });
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
};

startServer();

module.exports = app;
