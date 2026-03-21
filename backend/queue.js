const { Queue } = require('bullmq');
const IORedis = require('ioredis');

const redisOptions = {
    maxRetriesPerRequest: null,
    enableReadyCheck: false,
};

const connection = new IORedis(process.env.REDIS_URI || 'redis://localhost:6379', redisOptions);

const scanQueue = new Queue("scan-queue", { connection });

module.exports = {
  scanQueue,
  connection
};
