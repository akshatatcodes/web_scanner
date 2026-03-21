require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { scanUrl } = require('./scanner');
const { deepCrawl } = require('./engine');
const mongoose = require('mongoose');
const { scanQueue } = require('./queue');
const { Job } = require('bullmq');
require('./worker'); // start the worker



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

  })
  .catch(err => console.error('[Database] MongoDB connection error:', err));

// Routes

app.post('/api/scan', async (req, res) => {
  const { url } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    // Validate basic URL format
    const targetUrl = new URL(url.startsWith('http') ? url : `http://${url}`);
    
    const job = await scanQueue.add("basic-scan", {
      type: "basic-scan",
      target: targetUrl.href,
    }, {
      attempts: 3,
      backoff: { type: "exponential", delay: 2000 },
      timeout: 300000 // 5 minutes
    });

    res.json({ jobId: job.id });
  } catch (error) {
    console.error('Scan enqueue error:', error.message);
    res.status(500).json({ error: 'Failed to initiate the scan. Ensure URL is accessible.' });
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
    const job = await scanQueue.add("port-scan", {
      type: "port-scan",
      target: targetUrl.hostname,
    }, {
      attempts: 3,
      backoff: { type: "exponential", delay: 2000 },
      timeout: 300000 // 5 minutes
    });
    res.json({ jobId: job.id });
  } catch (error) {
    console.error('Port Scan enqueue error:', error.message);
    res.status(500).json({ error: 'Failed to start port scan.' });
  }
});

app.post('/api/deep-crawl', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  try {
    const targetUrl = new URL(url.startsWith('http') ? url : `http://${url}`);
    const job = await scanQueue.add("deep-crawl", {
      type: "deep-crawl",
      target: targetUrl.href,
    }, {
      attempts: 3,
      backoff: { type: "exponential", delay: 2000 },
      timeout: 300000 // 5 minutes
    });
    res.json({ jobId: job.id });
  } catch (error) {
    console.error('Deep crawl enqueue error:', error.message);
    res.status(500).json({ error: 'Deep crawl queueing failed.' });
  }
});

app.get('/api/jobs/:id', async (req, res) => {
  try {
    const job = await Job.fromId(scanQueue, req.params.id);

    if (!job) return res.status(404).json({ error: "Job not found" });

    const state = await job.getState();
    const isCompleted = state === "completed";
    
    // Some routes (like basic-scan and deeper scan logic) might return an object
    // wrap the returned values to mimic the old response if necessary.
    let finalResult = null;
    if (isCompleted && job.returnvalue) {
        finalResult = job.returnvalue;
    }

    res.json({
      jobId: job.id,
      state,
      progress: job.progress || 0,
      result: finalResult,
      failedReason: job.failedReason
    });
  } catch (error) {
    console.error('Job status fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch job status.' });
  }
});

app.listen(PORT, () => {
  console.log(`Web Security Exposure Analyzer backend running on http://localhost:${PORT}`);
});
