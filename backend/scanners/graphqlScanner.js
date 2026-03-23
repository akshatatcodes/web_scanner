const axios = require('axios');

const GRAPHQL_PATHS = [
  "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/graphql/v1"
];

const INTROSPECTION_QUERY = `{"query":"\\n    query IntrospectionQuery {\\n      __schema {\\n        queryType { name }\\n      }\\n    }\\n"}`;

const scanGraphQL = async (baseUrl) => {
  const findings = [];
  const urlBase = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;

  for (const path of GRAPHQL_PATHS) {
    try {
      const url = `${urlBase}${path}`;
      const res = await axios.post(url, INTROSPECTION_QUERY, {
        timeout: 5000,
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Scanner'
        },
        validateStatus: () => true
      });

      if (res.data && typeof res.data === 'object') {
        if (res.data.data && res.data.data.__schema) {
          findings.push({
            type: "GRAPHQL_EXPOSURE",
            severity: "HIGH",
            url,
            message: "GraphQL endpoint exposed with Introspection ENABLED"
          });
        } else if (res.data.errors && JSON.stringify(res.data.errors).toLowerCase().includes('graphql')) {
          findings.push({
            type: "GRAPHQL_EXPOSURE",
            severity: "INFO",
            url,
            message: "GraphQL endpoint detected (Introspection apparently disabled)"
          });
        } else if (res.data.message && typeof res.data.message === 'string' && res.data.message.toLowerCase().includes('graphql')) {
           findings.push({
            type: "GRAPHQL_EXPOSURE",
            severity: "INFO",
            url,
            message: "GraphQL endpoint detected via error message"
          });           
        }
      }
    } catch (err) {
      // Ignore network errors
    }
  }

  return findings;
};

module.exports = { scanGraphQL };
