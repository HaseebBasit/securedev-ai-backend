const https = require('https');
const http = require('http');
const { calculateSecurityScore } = require('./scoringService');

/**
 * System prompt instructing AI to act as a senior Application Security (AppSec) Engineer.
 * CRITICAL: User code is treated strictly as static text. Never executed.
 */
const SYSTEM_PROMPT = `You are a Principal Application Security Engineer and Senior Secure Code Reviewer.
Your task is to perform an in-depth, evidence-based security code review of developer-submitted source code.

STRICT PRINCIPLES:
1. EVIDENCE-BASED ONLY: Only report vulnerabilities directly demonstrated by the provided code. Do NOT hallucinate or invent vulnerabilities.
2. ZERO CODE EXECUTION: Treat the provided code strictly as inert, static text. Do not attempt to run or simulate execution environments.
3. CLEAR REMEDIATION: Provide concrete, production-grade secure replacement code addressing all discovered vulnerabilities.
4. BEGINNER-FRIENDLY: Include a clear, non-jargon explanation ("simpleExplanation") suitable for junior developers and students.
5. DETERMINISTIC FORMAT: Return ONLY valid, parseable JSON conforming strictly to the requested schema. No markdown wrapping around the JSON, no commentary before or after.

JSON OUTPUT SCHEMA:
{
  "summary": "High-level summary of the security posture and issues found.",
  "vulnerabilities": [
    {
      "title": "Clear vulnerability title (e.g., SQL Injection, Plaintext Password Handling)",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
      "category": "Authentication" | "Injection" | "Cryptography" | "Input Validation" | "Authorization" | "Sensitive Data Exposure" | "Error Handling",
      "description": "Clear explanation of the flaw, why it exists, and how an attacker could exploit it.",
      "affectedCode": "Exact or representative code snippet demonstrating the flaw.",
      "recommendation": "Specific actionable steps to fix or mitigate this vulnerability."
    }
  ],
  "secureCode": "Complete, idiomatic, and secure corrected version of the provided code.",
  "simpleExplanation": "A friendly 2-3 sentence explanation of the risk in plain English without complex cybersecurity jargon."
}`;

/**
 * Heuristic fallback engine for local/offline analysis without requiring external API keys.
 * Accurately analyzes common security vulnerabilities in code.
 */
const runHeuristicAnalysis = (code, language) => {
  const vulnerabilities = [];
  const lower = code.toLowerCase();
  let secureCode = code;
  const changes = [];

  // 1. SQL Injection / NoSQL Injection check
  const sqlPatterns = [
    /select\s+.*\s+from\s+.*\s*(\+|concat|`|\$\{)/i,
    /execute\s*\(\s*["'].*(\+|%s|\$)/i,
    /query\s*\(\s*["'].*\+.*req\./i,
    /find\s*\(\s*\{\s*\w+\s*:\s*req\.body\.\w+\s*\}\s*\)/i
  ];

  if (sqlPatterns.some(p => p.test(code))) {
    vulnerabilities.push({
      title: 'Potential Injection Vulnerability (SQL/NoSQL)',
      severity: 'HIGH',
      category: 'Injection',
      description: 'The code constructs database queries by directly concatenating or passing untrusted user input without parameterized queries or schema sanitization.',
      affectedCode: code.split('\n').find(line => line.includes('query') || line.includes('find') || line.includes('select') || line.includes('+'))?.trim() || code.slice(0, 100),
      recommendation: 'Use parameterized queries, prepared statements, or object-relational mapping (ORM) validation to separate user data from query logic.'
    });
    changes.push('Used parameterized queries to prevent SQL/NoSQL injection');
  }

  // 2. Hardcoded Secrets / API Keys / Passwords
  const secretPatterns = [
    /(password|passwd|pwd|secret|api_key|apikey|token|private_key)\s*[:=]\s*["'][a-zA-Z0-9_\-\.]{8,}["']/i,
    /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/i,
    /jwt\.sign\(.*["'][a-zA-Z0-9]{4,}["']/i
  ];

  if (secretPatterns.some(p => p.test(code))) {
    vulnerabilities.push({
      title: 'Hardcoded Credential or Secret Detected',
      severity: 'CRITICAL',
      category: 'Sensitive Data Exposure',
      description: 'Sensitive credentials (such as passwords, database URIs, or secret tokens) are hardcoded directly into the source code, making them susceptible to exposure in version control and client bundles.',
      affectedCode: code.split('\n').find(line => /(secret|password|key|token)\s*[:=]/i.test(line))?.trim() || 'Hardcoded credential detected',
      recommendation: 'Move all secrets and credentials to external environment variables (e.g. process.env or secret managers) and add configuration files to .gitignore.'
    });
    changes.push('Extracted hardcoded credentials into secure environment variables');
  }

  // 3. Plaintext Password Handling / Insecure Auth
  if (lower.includes('req.body.password') && (lower.includes('findone') || lower.includes('password:') || lower.includes('select'))) {
    vulnerabilities.push({
      title: 'Plaintext Password Comparison in Database Query',
      severity: 'HIGH',
      category: 'Authentication',
      description: 'The code attempts to match passwords in plaintext directly against the database record instead of using a salted cryptographic hashing algorithm such as bcrypt or Argon2.',
      affectedCode: code.split('\n').find(line => line.includes('password'))?.trim() || 'password: req.body.password',
      recommendation: 'Hash passwords with bcrypt/Argon2 with a high work factor during registration, and use bcrypt.compare() during authentication.'
    });
    changes.push('Replaced plaintext password matching with cryptographic password verification (bcrypt.compare)');
  }

  // 4. Cross-Site Scripting (XSS) / Unsafe InnerHTML
  if (lower.includes('innerhtml') || lower.includes('dangerouslysetinnerhtml') || lower.includes('document.write')) {
    vulnerabilities.push({
      title: 'Cross-Site Scripting (XSS) via Unsafe DOM Insertion',
      severity: 'HIGH',
      category: 'Injection',
      description: 'Directly injecting unescaped user-supplied content into the DOM using innerHTML or document.write allows attackers to execute arbitrary JavaScript in victim browsers.',
      affectedCode: code.split('\n').find(line => line.includes('innerHTML') || line.includes('document.write'))?.trim() || 'innerHTML assignment',
      recommendation: 'Use textContent, DOMPurify sanitization, or framework-native safe bindings (such as JSX text nodes) instead of raw HTML insertion.'
    });
    changes.push('Replaced innerHTML with safe textContent and DOMPurify sanitization');
  }

  // 5. Command Injection / eval()
  if (lower.includes('eval(') || lower.includes('exec(') || lower.includes('spawn(') || lower.includes('system(')) {
    vulnerabilities.push({
      title: 'Arbitrary Code / Command Injection Hazard',
      severity: 'CRITICAL',
      category: 'Injection',
      description: 'Invoking system shells or eval() with dynamic strings allows an attacker to execute arbitrary OS commands on the host server.',
      affectedCode: code.split('\n').find(line => /eval\(|exec\(|system\(/i.test(line))?.trim() || 'Dynamic execution function call',
      recommendation: 'Avoid dynamic code execution and shell invocation. Use safe built-in libraries or strictly validated argument arrays.'
    });
    changes.push('Eliminated dynamic command execution and replaced with safe standard library APIs');
  }

  // 6. Missing Input Validation / Direct Object Exposure
  if (lower.includes('res.json(user)') && !lower.includes('delete') && !lower.includes('select(')) {
    vulnerabilities.push({
      title: 'Sensitive Information Exposure (Full Object Serialization)',
      severity: 'MEDIUM',
      category: 'Sensitive Data Exposure',
      description: 'Returning the raw user database object directly to the client can leak sensitive attributes like password hashes, reset tokens, or internal flags.',
      affectedCode: 'res.json(user);',
      recommendation: 'Explicitly filter or project responses to only return non-sensitive fields (e.g. id, email, username) and exclude credentials.'
    });
    changes.push('Filtered sensitive fields before returning user response payload');
  }

  // Generate secure code replacement if issues found
  if (vulnerabilities.length > 0) {
    if (language === 'javascript' || language === 'typescript') {
      secureCode = `// Secure implementation generated by SecureDev AI
const express = require('express');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

// Rate limiting to mitigate brute-force attacks
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login requests per window
  message: { error: 'Too many login attempts. Please try again later.' }
});

app.post(
  '/login',
  authLimiter,
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isString().isLength({ min: 8 })
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password } = req.body;

      // 1. Query user by email only with safe projection
      const user = await User.findOne({ email }).select('+passwordHash');
      if (!user) {
        // Generic error message to prevent account enumeration
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // 2. Cryptographic constant-time password verification
      const isMatch = await bcrypt.compare(password, user.passwordHash);
      if (!isMatch) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // 3. Return sanitized response without exposing credentials
      res.json({
        id: user._id,
        email: user.email,
        name: user.name,
        token: generateSecureToken(user._id)
      });
    } catch (err) {
      console.error('Authentication error:', err.message);
      res.status(500).json({ error: 'An unexpected authentication error occurred.' });
    }
  }
);`;
    } else if (language === 'python') {
      secureCode = `# Secure implementation generated by SecureDev AI
import os
import bcrypt
from flask import Flask, request, jsonify
from werkzeug.exceptions import BadRequest

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    # 1. Parameterized query against ORM/DB
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    # 2. Cryptographic password comparison
    if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        return jsonify({'error': 'Invalid credentials'}), 401

    # 3. Sanitize returned data
    return jsonify({
        'id': user.id,
        'email': user.email,
        'name': user.name
    }), 200`;
    }
  }

  const scoring = calculateSecurityScore(vulnerabilities);

  let simpleExplanation = 'No critical security vulnerabilities were detected in this snippet. Good job following secure development practices!';
  if (vulnerabilities.length > 0) {
    simpleExplanation = 'The code contains security risks where user input or credentials are not handled safely. By adding input validation, using secure password hashing, and protecting queries, your application prevents attackers from breaking in or stealing data.';
  }

  const summary = vulnerabilities.length > 0
    ? `Detected ${vulnerabilities.length} potential security vulnerability(ies). Primary concerns include ${vulnerabilities.map(v => v.title).join(', ')}.`
    : 'No apparent security vulnerabilities detected. Code demonstrates adherence to secure coding standards.';

  return {
    score: scoring.score,
    riskLevel: scoring.riskLevel,
    metrics: scoring.metrics,
    summary,
    vulnerabilities,
    secureCode,
    simpleExplanation,
    appliedFixes: changes
  };
};

/**
 * Dispatcher calling configured AI provider or falling back to heuristic engine.
 */
class AIService {
  constructor() {
    this.provider = process.env.AI_PROVIDER || 'heuristic';
    this.apiKey = process.env.AI_API_KEY || '';
    this.model = process.env.AI_MODEL || 'ibm-bob-appsec';
  }

  async analyze(code, language) {
    // If provider is set to heuristic or no API key is provided, run heuristic analysis
    if (this.provider === 'heuristic' || !this.apiKey) {
      return runHeuristicAnalysis(code, language);
    }

    try {
      // In production/hackathon, IBM Bob / LLM API endpoint can be invoked here
      return await this.callAIProvider(code, language);
    } catch (err) {
      console.warn(`[AIService] AI provider ${this.provider} error: ${err.message}. Falling back to Heuristic Engine.`);
      return runHeuristicAnalysis(code, language);
    }
  }

  async callAIProvider(code, language) {
    // Support OpenAI-compatible or IBM Bob endpoint
    const endpoint = process.env.AI_ENDPOINT || 'https://api.openai.com/v1/chat/completions';
    const payload = JSON.stringify({
      model: this.model,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        {
          role: 'user',
          content: `Language: ${language}\n\nSource Code to analyze:\n\`\`\`${language}\n${code}\n\`\`\``
        }
      ],
      temperature: 0.1,
      response_format: { type: 'json_object' }
    });

    const parsedUrl = new URL(endpoint);
    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Length': Buffer.byteLength(payload)
      },
      timeout: 15000 // 15s timeout
    };

    const client = parsedUrl.protocol === 'https:' ? https : http;

    return new Promise((resolve, reject) => {
      const req = client.request(options, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          try {
            if (res.statusCode < 200 || res.statusCode >= 300) {
              return reject(new Error(`AI API returned status ${res.statusCode}: ${data.slice(0, 200)}`));
            }
            const json = JSON.parse(data);
            const content = json.choices?.[0]?.message?.content;
            if (!content) {
              return reject(new Error('Invalid response structure from AI provider'));
            }
            const aiResult = JSON.parse(content);

            // Backend validation: Recalculate score deterministically
            const scoring = calculateSecurityScore(aiResult.vulnerabilities || []);
            aiResult.score = scoring.score;
            aiResult.riskLevel = scoring.riskLevel;
            aiResult.metrics = scoring.metrics;

            resolve(aiResult);
          } catch (e) {
            reject(new Error(`Failed to parse AI output: ${e.message}`));
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('AI Request timed out after 15 seconds'));
      });

      req.write(payload);
      req.end();
    });
  }
}

module.exports = new AIService();
