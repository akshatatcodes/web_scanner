const pLimit = require('p-limit');
const axios = require('axios');

const safeRequest = async (fn, retries = 3) => {
  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (e) {
      if (i === retries - 1) return null;
      // Exponential backoff
      await new Promise(r => setTimeout(r, 1000 * (i + 1)));
    }
  }
  return null;
};

module.exports = { pLimit, safeRequest };
