const mongoose = require('mongoose');

const VulnerabilitySchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true,
  },
  severity: {
    type: String,
    enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
    required: true,
  },
  category: {
    type: String,
    required: true,
    trim: true,
  },
  description: {
    type: String,
    required: true,
  },
  affectedCode: {
    type: String,
    default: '',
  },
  recommendation: {
    type: String,
    required: true,
  },
}, { _id: false });

const AnalysisSchema = new mongoose.Schema(
  {
    language: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    },
    score: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
    },
    riskLevel: {
      type: String,
      enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      required: true,
    },
    summary: {
      type: String,
      required: true,
    },
    vulnerabilities: [VulnerabilitySchema],
    secureCode: {
      type: String,
      default: '',
    },
    simpleExplanation: {
      type: String,
      default: '',
    },
    metrics: {
      criticalCount: { type: Number, default: 0 },
      highCount: { type: Number, default: 0 },
      mediumCount: { type: Number, default: 0 },
      lowCount: { type: Number, default: 0 },
      infoCount: { type: Number, default: 0 },
    },
  },
  {
    timestamps: true,
    collection: 'analyses',
  }
);

// Index for efficient query of recent analyses
AnalysisSchema.index({ createdAt: -1 });

module.exports = mongoose.model('Analysis', AnalysisSchema);
