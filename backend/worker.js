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
        const result = await scanUrl(target);
        await job.updateProgress({ message: "Scan completed", percentage: 100 });
        return result;
      }

      if (type === "deep-crawl") {
        await job.updateProgress({ message: "Initializing deep crawl...", percentage: 10 });
        const result = await deepCrawl(target);
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
      concurrency: 5,
      lockDuration: 60000,   // Increase to 60s
      lockRenewTime: 20000   // Renew every 20s
  }
);

worker.on('completed', job => {
  console.log(`[Worker] Job ${job.id} has completed!`);
});

worker.on('failed', (job, err) => {
  console.log(`[Worker] Job ${job.id} has failed with ${err.message}`);
});

module.exports = worker;
