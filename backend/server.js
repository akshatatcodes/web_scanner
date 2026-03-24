require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { scanUrl } = require('./scanner');
const { deepCrawl } = require('./engine');
const mongoose = require('mongoose');
const { scanQueue } = require('./queue');
const { Job } = require('bullmq');
const attackLogger = require('./utils/attackLogger');
const aiService = require('./services/aiService');
const reportGenerator = require('./utils/reportGenerator');
const persistence = require('./utils/persistence');
const crypto = require('crypto');
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
      jobId: crypto.randomUUID(),
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
      jobId: crypto.randomUUID(),
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
      jobId: crypto.randomUUID(),
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

app.post('/api/ai/analyze', async (req, res) => {
    const { finding } = req.body;
    if (!finding) return res.status(400).json({ error: 'Finding is required' });

    try {
        const analysis = await aiService.analyze(finding);
        res.json(analysis);
    } catch (error) {
        console.error('AI Analysis error:', error.message);
        res.status(500).json({ error: 'AI Layer failed to process the finding.' });
    }
});

// Server-Sent Events: Live Attack Console

app.get('/api/attack-stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.flushHeaders();

  // Send a heartbeat every 15s to keep connection alive
  const heartbeat = setInterval(() => {
    res.write('event: heartbeat\ndata: {}\n\n');
  }, 15000);

  // Forward attack log events to this SSE client
  const onLog = (entry) => {
    res.write(`data: ${JSON.stringify(entry)}\n\n`);
  };

  attackLogger.on('attack-log', onLog);

  // Cleanup when client disconnects
  req.on('close', () => {
    clearInterval(heartbeat);
    attackLogger.off('attack-log', onLog);
  });
});

// Report Generation Endpoint
app.get('/api/reports/:format/:jobId', async (req, res) => {
    const { format, jobId } = req.params;

    if (!['pdf', 'html'].includes(format)) {
        return res.status(400).json({ error: 'Invalid format. Use "pdf" or "html".' });
    }

    try {
        // 1. Check if report already exists on disk (cache)
        const existingPath = await persistence.getReport(jobId, format);
        if (existingPath && format !== 'html') {
            console.log(`[Reports] Serving cached report for job: ${jobId}`);
            return res.sendFile(existingPath);
        }

        // 2. Retrieve job and results
        const job = await Job.fromId(scanQueue, jobId);
        if (!job) return res.status(404).json({ error: 'Job not found' });

        const state = await job.getState();
        if (state !== 'completed') {
            return res.status(400).json({ error: `Report cannot be generated. Job status: ${state}` });
        }

        const results = job.returnvalue;
        if (!results) return res.status(404).json({ error: 'Scan results not found for this job' });

        // 3. Generate Report
        let content;
        if (format === 'html') {
            content = reportGenerator.generateHtml(results);
            res.setHeader('Content-Type', 'text/html');
        } else {
            console.log(`[Reports] Generating PDF for job: ${jobId}...`);
            content = await reportGenerator.generatePdf(results);
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `attachment; filename="Security_Report_${jobId}.pdf"`);
        }

        // 4. Save to disk (persistence)
        await persistence.saveReport(jobId, format, content);

        // 5. Send response
        res.send(content);

    } catch (error) {
        console.error('[Reports] Error generating report:', error.message);
        res.status(500).json({ error: 'Internal server error during report generation.' });
    }
});

app.listen(PORT, () => {
  console.log(`Web Security Exposure Analyzer backend running on http://localhost:${PORT}`);
});

