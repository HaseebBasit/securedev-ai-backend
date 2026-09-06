const SUPPORTED_LANGUAGES = [
  'javascript',
  'typescript',
  'python',
  'java',
  'php',
  'csharp',
  'cpp',
  'go'
];

const LANGUAGE_DISPLAY_NAMES = {
  javascript: 'JavaScript',
  typescript: 'TypeScript',
  python: 'Python',
  java: 'Java',
  php: 'PHP',
  csharp: 'C#',
  cpp: 'C++',
  go: 'Go'
};

const MAX_CODE_LENGTH = 64000; // 64 KB of text limit to prevent ReDoS and token exhaustion

const isValidLanguage = (lang) => {
  if (!lang || typeof lang !== 'string') return false;
  return SUPPORTED_LANGUAGES.includes(lang.trim().toLowerCase());
};

const sanitizeInputCode = (code) => {
  if (typeof code !== 'string') return '';
  return code.trim();
};

module.exports = {
  SUPPORTED_LANGUAGES,
  LANGUAGE_DISPLAY_NAMES,
  MAX_CODE_LENGTH,
  isValidLanguage,
  sanitizeInputCode
};
