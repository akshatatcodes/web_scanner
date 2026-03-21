const dns = require('dns').promises;

/**
 * Enhanced DNS Scanner Module
 * Analyzes domain records and identifies security configuration gaps.
 */
async function scan(input) {
    try {
        let domain = input;
        if (input && typeof input === 'string' && input.includes('://')) {
            domain = new URL(input).hostname;
        }

        // Resolve records in parallel
        const [a, aaaa, mx, txt, ns] = await Promise.allSettled([
            dns.resolve(domain, 'A'),
            dns.resolve(domain, 'AAAA'),
            dns.resolveMx(domain),
            dns.resolveTxt(domain),
            dns.resolve(domain, 'NS')
        ]);

        const records = {
            A: a.status === 'fulfilled' ? a.value : [],
            AAAA: aaaa.status === 'fulfilled' ? aaaa.value : [],
            MX: mx.status === 'fulfilled' ? mx.value.map(m => m.exchange) : [],
            TXT: txt.status === 'fulfilled' ? txt.value.flat() : [],
            NS: ns.status === 'fulfilled' ? ns.value : []
        };

        const issues = [];
        
        // Security Check: SPF Record
        const hasSPF = records.TXT.some(txt => txt.toLowerCase().includes('v=spf1'));
        if (!hasSPF) {
            issues.push({
                severity: 'medium',
                issue: 'Missing SPF Record',
                code: 'MISSING_SPF',
                description: 'Domain does not define a Sender Policy Framework (SPF) record, which helps prevent email spoofing.',
                recommendation: 'Configure an SPF TXT record to authorized mail servers.'
            });
        }

        // Security Check: DMARC Record
        const dmarcDomain = `_dmarc.${domain}`;
        let hasDMARC = false;
        try {
            const dmarcRecords = await dns.resolveTxt(dmarcDomain);
            hasDMARC = dmarcRecords.some(txt => txt.join('').toLowerCase().includes('v=dmarc1'));
        } catch (e) {}

        if (!hasDMARC) {
            issues.push({
                severity: 'medium',
                issue: 'Missing DMARC Record',
                code: 'MISSING_DMARC',
                description: 'Domain does not have a DMARC policy, making it vulnerable to email impersonation.',
                recommendation: 'Enable DMARC to define how receiving servers should handle emails that fail SPF/DKIM checks.'
            });
        }

        // Security Check: DKIM (Common selector check)
        // Note: DKIM checks are trickier because of selectors. We'll check for 'google._domainkey' or generic 'dkim' if possible.
        const selectors = ['google', 'default', 'dkim', 'mandrill', 'mailgun'];
        let hasDKIM = false;
        for (const selector of selectors) {
            try {
                const dkimRecords = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
                if (dkimRecords.some(txt => txt.join('').toLowerCase().includes('v=dkim1'))) {
                    hasDKIM = true;
                    break;
                }
            } catch (e) {}
        }

        if (!hasDKIM) {
            issues.push({
                severity: 'low',
                issue: 'Missing DKIM Records',
                code: 'MISSING_DKIM',
                description: 'Domain is missing standard DKIM records for common mail providers.',
                recommendation: 'Configure DKIM (DomainKeys Identified Mail) to add a digital signature to your emails.'
            });
        }

        return {
            records,
            issues
        };
    } catch (error) {
        console.error('[DNS Scanner] Error:', error.message);
        return { error: 'Failed to resolve DNS records', issues: [] };
    }
}

module.exports = { scan };
