require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { scanUrl } = require('./scanner');
const mongoose = require('mongoose');
const monitorRoutes = require('./routes/monitorRoutes');
const { startMonitoring } = require('./services/monitorService');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/web-scanner';
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('[Database] Connected to MongoDB');
    startMonitoring(); // Start background scheduler only after DB connects
  })
  .catch(err => console.error('[Database] MongoDB connection error:', err));

// Routes
app.use('/api/monitor', monitorRoutes);

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

const portScanner = require('./scanners/portScanner');
app.post('/api/scan-ports', async (req, res) => {
  const { url, permission } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }
  
  if (!permission) {
    return res.status(403).json({ error: 'Port scanning requires user permission confirmation.' });
  }

  try {
    const targetUrl = new URL(url.startsWith('http') ? url : `http://${url}`);
    const results = await portScanner.scan(targetUrl.hostname);
    res.json({ portScan: results });
  } catch (error) {
    console.error('Port Scan error:', error.message);
    res.status(500).json({ error: 'Failed to scan ports.' });
  }
});

app.listen(PORT, () => {
  console.log(`Web Security Exposure Analyzer backend running on http://localhost:${PORT}`);
});
