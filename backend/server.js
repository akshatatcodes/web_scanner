const express = require('express');
const cors = require('cors');
const { scanUrl } = require('./scanner');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

app.post('/api/scan', async (req, res) => {
  const { url } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    // Validate basic URL format
    const targetUrl = new URL(url.startsWith('http') ? url : `http://${url}`);
    
    const results = await scanUrl(targetUrl.href);
    res.json(results);
  } catch (error) {
    console.error('Scan error:', error.message);
    res.status(500).json({ error: 'Failed to scan the URL. Ensure it is accessible.' });
  }
});

app.listen(PORT, () => {
  console.log(`Web Security Exposure Analyzer backend running on http://localhost:${PORT}`);
});
