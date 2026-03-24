# Free AI Integration Guide

Vulnexa uses AI to instantly analyze, explain, and write remediation code for discovered vulnerabilities. You can easily integrate **completely free APIs** to power this engine without spending any money.

## Option 1: Google Gemini API (Recommended & Free forever)
Google offers an incredibly generous free tier for Google Gemini (up to 15 Requests Per Minute), which is perfect for this tool!

### Setup Steps:
1. Go to **[Google AI Studio](https://aistudio.google.com/app/apikey)** (you just need a standard Google Account).
2. Click **"Get API key"** on the left menu, and hit **"Create API key in new project"**.
3. Copy the incredibly long generated string.
4. Open the `backend/.env` file in the scanner repository.
5. Paste it in exactly like this:
   ```env
   GEMINI_API_KEY=AIzaSy...your_key_here...
   # Ensure OPENAI_API_KEY is left empty!
   OPENAI_API_KEY=
   ```
6. Restart your backend (`npm start`). Your "AI Details" tab will now be fully operational!

---

## Option 2: Groq API (Incredibly Fast & Free)
If you prefer Llama 3 or want insanely fast speeds, Groq is the best free alternative. It offers 14,000 requests per day entirely for free!

### Setup Steps:
1. Visit the **[Groq Console](https://console.groq.com/keys)** and sign up.
2. Click **Create API Key** and copy it (`gsk_...`).
3. To use Groq, you will need to tweak the `aiService.js` file in your backend to point to Groq's proxy URL (since they offer an OpenAI-compatible endpoint).
4. Update `backend/.env`:
   ```env
   OPENAI_API_KEY=gsk_your_groq_key
   # You must also pass the baseURL inside your aiService initialization
   # new OpenAI({ apiKey: process.env.OPENAI_API_KEY, baseURL: "https://api.groq.com/openai/v1" })
   ```

## Checking if it works
After you restart your backend with your new API key:
1. Run a Vulnerability scan from the UI.
2. Under "Exploit Proof", click the **"AI Assistant"** tab.
3. If it generates a live remediation plan and fix logic, you are all good to go!
