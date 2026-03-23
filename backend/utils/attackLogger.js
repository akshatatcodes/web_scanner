const { EventEmitter } = require('events');

/**
 * Global singleton event emitter for live attack logging.
 * Scanners call attackLogger.log(...) to emit events.
 * The SSE endpoint subscribes and pushes events to connected frontends.
 */
class AttackLogger extends EventEmitter {
    constructor() {
        super();
        this.setMaxListeners(50); // allow many SSE clients
    }

    /**
     * Emit an attack event.
     * @param {object} event
     * @param {string} event.jobId   - Associated job ID
     * @param {string} event.type    - 'SEND' | 'RECV' | 'FOUND' | 'INFO' | 'ERROR'
     * @param {string} event.scanner - Which scanner emitted this (e.g. 'SQLi', 'CmdInj')
     * @param {string} [event.url]   - Target URL
     * @param {string} [event.payload] - Attack payload sent
     * @param {number} [event.status]  - HTTP response status
     * @param {string} [event.result]  - FOUND/outcome message
     * @param {string} [event.severity] - CRITICAL | HIGH | MEDIUM | LOW
     */
    log(event) {
        const entry = {
            ...event,
            ts: Date.now(),
        };
        this.emit('attack-log', entry);
    }
}

const attackLogger = new AttackLogger();

module.exports = attackLogger;
