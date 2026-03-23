/**
 * evasion.js - Adaptive Evasion Strategy Engine
 * Provides multiple obfuscation techniques to bypass WAF filters.
 */

const strategies = {
    url_encode: (payload) => encodeURIComponent(payload),
    
    double_encode: (payload) => encodeURIComponent(encodeURIComponent(payload)),
    
    case_variation: (payload) => {
        return payload.split('').map((char, i) => 
            i % 2 === 0 ? char.toLowerCase() : char.toUpperCase()
        ).join('');
    },
    
    comment_injection: (payload) => {
        // Simple SQL/JS comment injection: ' OR 1=1 -> '/**/OR/**/1=1
        return payload.replace(/\s+/g, '/**/');
    },
    
    null_byte: (payload) => `%00${payload}`,
    
    hex_entities: (payload) => {
        return payload.split('').map(char => `&#x${char.charCodeAt(0).toString(16)};`).join('');
    },

    char_replacement: (payload) => {
        // Replace sensitive chars with equivalents if applicable
        return payload
            .replace(/'/g, '%27')
            .replace(/"/g, '%22')
            .replace(/</g, '%3c')
            .replace(/>/g, '%3e');
    }
};

/**
 * Apply a specific evasion strategy to a payload.
 */
function applyStrategy(payload, strategyName) {
    if (strategies[strategyName]) {
        return strategies[strategyName](payload);
    }
    return payload;
}

/**
 * Get all available strategy names.
 */
function getStrategies() {
    return Object.keys(strategies);
}

module.exports = {
    applyStrategy,
    getStrategies
};
