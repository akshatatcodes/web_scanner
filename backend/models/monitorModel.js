const mongoose = require('mongoose');

const monitorSchema = new mongoose.Schema({
  url: {
    type: String,
    required: true,
    unique: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastScan: Date,
  lastResult: {
    type: Object,
    default: null
  },
  isActive: {
    type: Boolean,
    default: true
  }
});

module.exports = mongoose.model('MonitoredDomain', monitorSchema);
