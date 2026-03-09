# web_scanner

A **Web Security Exposure Analyzer** that detects technology stacks and security exposures on any website.

## Tech Stack
- **Frontend**: React 18 + Vite
- **Backend**: Node.js + Express
- **Scanner Engine**: Node.js (Puppeteer + axios + cheerio)

## Features (Phase 1 — MVP)
- Detect frontend frameworks (React, Vue, Angular, Svelte, Next.js, etc.)
- Detect backend technologies (PHP, Node.js, ASP.NET, Django, Rails, etc.)
- Detect CMS platforms (WordPress, Shopify, Joomla, Drupal, Wix, etc.)
- Detect web servers (Apache, Nginx, IIS, LiteSpeed, etc.)
- Detect CDNs (Cloudflare, Akamai, CloudFront, Fastly, etc.)
- Detect analytics tools (Google Analytics, GTM, Facebook Pixel, Hotjar, etc.)

## Running Locally

```bash
# Backend (port 5000)
cd backend
npm install
node server.js

# Frontend (port 5173)
cd frontend
npm install
npm run dev
```
