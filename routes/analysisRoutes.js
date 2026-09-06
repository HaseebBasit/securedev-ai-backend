const express = require('express');
const router = express.Router();
const {
  healthCheck,
  analyzeCode,
  getAnalyses,
  getAnalysisById,
  getStats
} = require('../controllers/analysisController');
const { validateAnalyzeRequest } = require('../middleware/validationMiddleware');
const { analyzeLimiter } = require('../middleware/rateLimitMiddleware');

// Health Check
router.get('/health', healthCheck);

// Primary Analysis Endpoint
router.post('/analyze', analyzeLimiter, validateAnalyzeRequest, analyzeCode);

// Historical Analyses (Metadata)
router.get('/analyses', getAnalyses);
router.get('/analyses/:id', getAnalysisById);

// Aggregate Dashboard Statistics
router.get('/stats', getStats);

module.exports = router;
