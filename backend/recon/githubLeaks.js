const axios = require('axios');
const { safeRequest } = require('./utils');

const searchGithubLeaks = async (domain) => {
    try {
        const query = `"${domain}" (password OR api_key OR aws_access_key OR secret OR .env)`;
        const encodedQuery = encodeURIComponent(query);
        const url = `https://api.github.com/search/code?q=${encodedQuery}&per_page=10`;

        const headers = { 
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'SecurityAnalyzerBot'
        };

        if (process.env.GITHUB_TOKEN) {
            headers['Authorization'] = `token ${process.env.GITHUB_TOKEN}`;
        }

        const res = await safeRequest(() => axios.get(url, { headers, timeout: 8000 }), 1); // 1 retry only

        if (res && res.data) {
            return {
                leaksFound: res.data.total_count > 0,
                totalCount: res.data.total_count,
                sampleUrls: (res.data.items || []).slice(0, 3).map(item => item.html_url)
            };
        }
    } catch (err) {
        // usually 403 rate limit if no token provided
    }
    
    return { leaksFound: false, totalCount: 0, sampleUrls: [] };
};

module.exports = { searchGithubLeaks };
