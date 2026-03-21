const axios = require("axios");

const ADMIN_PATHS = [
  "/admin",
  "/admin/login",
  "/admin-panel",
  "/administrator",
  "/dashboard",
  "/backend",
  "/panel",
  "/manage",
  "/controlpanel",
  "/cpanel",
  "/login"
];

const scanAdminPanels = async (baseUrl) => {
  const findings = [];

  for (const path of ADMIN_PATHS) {
    try {
      const url = `${baseUrl}${path}`;

      const res = await axios.get(url, {
        timeout: 5000,
        validateStatus: () => true
      });

      if ([200,401,403].includes(res.status)) {
        findings.push({
          type: "ADMIN_PANEL",
          severity: "MEDIUM",
          url,
          message: "Potential admin panel discovered"
        });
      }

    } catch (err) {}
  }

  return findings;
};

module.exports = { scanAdminPanels };
