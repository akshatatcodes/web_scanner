const { Worker } = require('bullmq');
const { scanQueue, connection } = require('./queue');
const { scanUrl } = require('./scanner');
const { deepCrawl } = require('./engine');
const portScanner = require('./scanners/portScanner');

const worker = new Worker(
  "scan-queue",
  async (job) => {
    const { type, target, options } = job.data;

    try {
      if (type === "basic-scan") {
        await job.updateProgress({ message: "Initializing scan...", percentage: 10 });
        const result = await scanUrl(target, { job });
        await job.updateProgress({ message: "Scan completed", percentage: 100 });
        return result;
      }

      if (type === "deep-crawl") {
        await job.updateProgress({ message: "Initializing deep crawl...", percentage: 10 });
        const result = await deepCrawl(target, job);
        await job.updateProgress({ message: "Deep crawl completed", percentage: 100 });
        return result;
      }

      if (type === "port-scan") {
        await job.updateProgress({ message: "Initializing port scan...", percentage: 10 });
        const result = await portScanner.scan(target);
        await job.updateProgress({ message: "Port scan completed", percentage: 100 });
        return result;
      }
      
      throw new Error(`Unknown job type: ${type}`);
    } catch (error) {
        console.error(`[Worker] Job ${job.id} failed:`, error.message);
        throw error;
    }
  },
  { 
      connection, 
      concurrency: 1,         // Reduced to 1 for maximum stability
      lockDuration: 600000,   // Increased to 10 minutes (600s)
      maxStalledCount: 1      // Minimize retries to avoid concurrent workers for the same job
  }
);

worker.on('completed', job => {
  console.log(`[Worker] Job ${job.id} has completed!`);
});

worker.on('failed', (job, err) => {
  console.log(`[Worker] Job ${job.id} has failed with ${err.message}`);
});

module.exports = worker;
