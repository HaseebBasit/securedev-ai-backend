/**
 * Deterministic Security Scoring Service
 * 
 * Formula:
 * Base Score: 100
 * Deductions:
 *   - CRITICAL: -30 per issue
 *   - HIGH:     -20 per issue
 *   - MEDIUM:   -10 per issue
 *   - LOW:      -5  per issue
 *   - INFO:      0  per issue
 * Clamp: 0 to 100
 * 
 * Risk Bands:
 *   - 80 - 100: LOW
 *   - 60 - 79:  MEDIUM
 *   - 40 - 59:  HIGH
 *   - 0  - 39:  CRITICAL
 */

const DEDUCTIONS = {
  CRITICAL: 30,
  HIGH: 20,
  MEDIUM: 10,
  LOW: 5,
  INFO: 0
};

const calculateSecurityScore = (vulnerabilities = []) => {
  let totalDeduction = 0;
  const breakdown = [];
  const metrics = {
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    infoCount: 0
  };

  vulnerabilities.forEach(vuln => {
    const severity = (vuln.severity || 'LOW').toUpperCase();
    const penalty = DEDUCTIONS[severity] !== undefined ? DEDUCTIONS[severity] : 5;

    switch (severity) {
      case 'CRITICAL':
        metrics.criticalCount++;
        break;
      case 'HIGH':
        metrics.highCount++;
        break;
      case 'MEDIUM':
        metrics.mediumCount++;
        break;
      case 'LOW':
        metrics.lowCount++;
        break;
      default:
        metrics.infoCount++;
        break;
    }

    if (penalty > 0) {
      totalDeduction += penalty;
      breakdown.push({
        title: vuln.title,
        severity,
        deduction: penalty
      });
    }
  });

  const rawScore = 100 - totalDeduction;
  const score = Math.max(0, Math.min(100, rawScore));

  let riskLevel = 'LOW';
  if (score <= 39) {
    riskLevel = 'CRITICAL';
  } else if (score <= 59) {
    riskLevel = 'HIGH';
  } else if (score <= 79) {
    riskLevel = 'MEDIUM';
  } else {
    riskLevel = 'LOW';
  }

  return {
    score,
    riskLevel,
    totalDeduction,
    metrics,
    breakdown
  };
};

module.exports = {
  DEDUCTIONS,
  calculateSecurityScore
};
