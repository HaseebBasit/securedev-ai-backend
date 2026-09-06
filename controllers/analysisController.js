const aiService = require('../services/aiService');
const { calculateSecurityScore } = require('../services/scoringService');
const Analysis = require('../models/Analysis');
const { getDBStatus } = require('../config/database');
const safeLogger = require('../utils/safeLogger');
const crypto = require('crypto');

// In-memory cache for graceful fallback when MongoDB is not connected
const inMemoryAnalyses = [];

const healthCheck = (req, res) => {
  const dbStatus = getDBStatus();
  res.status(200).json({
    status: 'ok',
    service: 'SecureDev AI Backend',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    database: {
      connected: dbStatus.isConnected,
      mode: dbStatus.isConnected ? 'persistent (MongoDB Atlas)' : 'stateless (in-memory fallback)'
    }
  });
};

const analyzeCode = async (req, res, next) => {
  try {
    const { language, code } = req.sanitizedBody;
    safeLogger.audit('ANALYZE_REQUEST', { language, codeLength: code.length });

    // Step 1: Run security analysis through AI service abstraction
    const aiResult = await aiService.analyze(code, language);

    // Step 2: Enforce deterministic score calculation
    const scoring = calculateSecurityScore(aiResult.vulnerabilities || []);

    const resultPayload = {
      language,
      score: scoring.score,
      riskLevel: scoring.riskLevel,
      summary: aiResult.summary || 'Security review completed.',
      vulnerabilities: aiResult.vulnerabilities || [],
      secureCode: aiResult.secureCode || '',
      simpleExplanation: aiResult.simpleExplanation || '',
      metrics: scoring.metrics,
      appliedFixes: aiResult.appliedFixes || [],
      createdAt: new Date().toISOString()
    };

    // Step 3: Optional persistence in MongoDB (saving metadata only, never raw user source code)
    const dbStatus = getDBStatus();
    let savedId = null;

    if (dbStatus.isConnected) {
      try {
        const savedDoc = await Analysis.create({
          language: resultPayload.language,
          score: resultPayload.score,
          riskLevel: resultPayload.riskLevel,
          summary: resultPayload.summary,
          vulnerabilities: resultPayload.vulnerabilities,
          secureCode: resultPayload.secureCode,
          simpleExplanation: resultPayload.simpleExplanation,
          metrics: resultPayload.metrics
        });
        savedId = savedDoc._id;
      } catch (dbErr) {
        safeLogger.warn(`Failed to persist to MongoDB: ${dbErr.message}`);
      }
    }

    if (!savedId) {
      // In-memory fallback tracking
      savedId = crypto.randomUUID();
      inMemoryAnalyses.unshift({
        _id: savedId,
        ...resultPayload
      });
      if (inMemoryAnalyses.length > 50) {
        inMemoryAnalyses.pop();
      }
    }

    resultPayload.id = savedId;

    return res.status(200).json({
      success: true,
      ...resultPayload
    });
  } catch (error) {
    next(error);
  }
};

const getAnalyses = async (req, res, next) => {
  try {
    const dbStatus = getDBStatus();
    const limit = Math.min(parseInt(req.query.limit, 10) || 20, 50);

    if (dbStatus.isConnected) {
      const records = await Analysis.find()
        .sort({ createdAt: -1 })
        .limit(limit)
        .select('-__v');
      return res.status(200).json({
        success: true,
        count: records.length,
        analyses: records
      });
    }

    // In-memory fallback
    const records = inMemoryAnalyses.slice(0, limit);
    return res.status(200).json({
      success: true,
      count: records.length,
      analyses: records,
      mode: 'in-memory'
    });
  } catch (error) {
    next(error);
  }
};

const getAnalysisById = async (req, res, next) => {
  try {
    const { id } = req.params;
    const dbStatus = getDBStatus();

    if (dbStatus.isConnected) {
      const analysis = await Analysis.findById(id).select('-__v');
      if (!analysis) {
        return res.status(404).json({ success: false, error: 'Analysis record not found' });
      }
      return res.status(200).json({ success: true, analysis });
    }

    // In-memory search
    const analysis = inMemoryAnalyses.find(a => a._id === id);
    if (!analysis) {
      return res.status(404).json({ success: false, error: 'Analysis record not found' });
    }
    return res.status(200).json({ success: true, analysis });
  } catch (error) {
    next(error);
  }
};

const getStats = async (req, res, next) => {
  try {
    const dbStatus = getDBStatus();

    if (dbStatus.isConnected) {
      const totalAnalyses = await Analysis.countDocuments();
      const pipeline = [
        {
          $group: {
            _id: null,
            avgScore: { $avg: '$score' },
            totalCritical: { $sum: '$metrics.criticalCount' },
            totalHigh: { $sum: '$metrics.highCount' },
            totalMedium: { $sum: '$metrics.mediumCount' },
            totalLow: { $sum: '$metrics.lowCount' }
          }
        }
      ];
      const statsResult = await Analysis.aggregate(pipeline);
      const agg = statsResult[0] || {};

      return res.status(200).json({
        success: true,
        totalAnalyses,
        averageScore: agg.avgScore ? Math.round(agg.avgScore) : 100,
        riskDistribution: {
          critical: agg.totalCritical || 0,
          high: agg.totalHigh || 0,
          medium: agg.totalMedium || 0,
          low: agg.totalLow || 0
        }
      });
    }

    // In-memory stats
    const total = inMemoryAnalyses.length;
    const avgScore = total > 0
      ? Math.round(inMemoryAnalyses.reduce((acc, a) => acc + (a.score || 0), 0) / total)
      : 85;
    const critical = inMemoryAnalyses.reduce((acc, a) => acc + (a.metrics?.criticalCount || 0), 0);
    const high = inMemoryAnalyses.reduce((acc, a) => acc + (a.metrics?.highCount || 0), 0);
    const medium = inMemoryAnalyses.reduce((acc, a) => acc + (a.metrics?.mediumCount || 0), 0);
    const low = inMemoryAnalyses.reduce((acc, a) => acc + (a.metrics?.lowCount || 0), 0);

    return res.status(200).json({
      success: true,
      totalAnalyses: total,
      averageScore: avgScore,
      riskDistribution: { critical, high, medium, low },
      mode: 'in-memory'
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  healthCheck,
  analyzeCode,
  getAnalyses,
  getAnalysisById,
  getStats
};
