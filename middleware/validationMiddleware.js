const { isValidLanguage, MAX_CODE_LENGTH, sanitizeInputCode, SUPPORTED_LANGUAGES } = require('../utils/validators');

const validateAnalyzeRequest = (req, res, next) => {
  const { language, code } = req.body || {};

  // Check language presence & validity
  if (!language || typeof language !== 'string') {
    return res.status(400).json({
      success: false,
      error: `Missing required field: 'language'. Supported languages: ${SUPPORTED_LANGUAGES.join(', ')}.`
    });
  }

  const normalizedLang = language.trim().toLowerCase();
  if (!isValidLanguage(normalizedLang)) {
    return res.status(400).json({
      success: false,
      error: `Unsupported programming language '${language}'. Supported languages: ${SUPPORTED_LANGUAGES.join(', ')}.`
    });
  }

  // Check code presence
  if (!code || typeof code !== 'string') {
    return res.status(400).json({
      success: false,
      error: `Missing required field: 'code'. Please provide valid source code text to analyze.`
    });
  }

  const sanitized = sanitizeInputCode(code);
  if (sanitized.length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Submitted code snippet is empty. Please provide source code to analyze.'
    });
  }

  // Check code length limits to prevent DoS
  if (sanitized.length > MAX_CODE_LENGTH) {
    return res.status(413).json({
      success: false,
      error: `Code length (${sanitized.length} characters) exceeds the maximum allowed limit of ${MAX_CODE_LENGTH} characters.`
    });
  }

  // Attach sanitized fields to request
  req.sanitizedBody = {
    language: normalizedLang,
    code: sanitized
  };

  next();
};

module.exports = {
  validateAnalyzeRequest
};
