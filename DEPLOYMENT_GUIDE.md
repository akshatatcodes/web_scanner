# 🚀 Ultimate Deployment Guide: Web Security Analyzer

Deploying this professional security scanner involves hosting the **Frontend** on Vercel and the **Backend** on Render, while securely connecting them to your **Upstash Redis** and **MongoDB Atlas** databases. 

Follow these steps exactly to get everything live on the internet!

---

## Part 1: Preparing Your Databases

### 1. Configure MongoDB Atlas (`MONGO_URI`)
You successfully created your cluster, but your connection string contains a placeholder (`<electron>`) that must be replaced.

Your current string:  
`mongodb+srv://akshatcodesat_db_user:<electron>@cluster0.tmb7g6y.mongodb.net/?appName=Cluster0`

**ACTION REQUIRED:**
1. Replace `<electron>` with the exact password you typed when creating the `akshatcodesat_db_user` user. 
2. If your password is `MySecretPassword123`, your final string will be:
   `mongodb+srv://akshatcodesat_db_user:MySecretPassword123@cluster0.tmb7g6y.mongodb.net/?appName=Cluster0`
3. **Copy this final string and save it to Notepad.**

### 2. Configure Upstash Redis (`REDIS_URI`)
Our high-performance Background Worker uses **BullMQ**, which requires a native Redis TCP connection, NOT a REST API URL.

**ACTION REQUIRED:**
1. Go to your [Upstash Dashboard](https://console.upstash.com/redis).
2. Click on your database (`awaited-impala-82508`).
3. Scroll down to the **"Connect to your database"** section.
4. In the dropdown (where it says REST by default), click it and select **Node.js (ioredis)** or **Redis CLI**.
5. You will see a password-protected connection string that starts with `rediss://`. 
   *(It will look something like this: `rediss://default:gQAAAAAAAUJMAAInc...282508@awaited-impala-82508.upstash.io:32508`)*
6. **Copy that entire `rediss://...` string and save it to Notepad.**

---

## Part 2: Deploying the Backend (Render.com)

Our Backend connects to MongoDB and Redis to perform the heavy lifting, running the Headless Browser (Puppeteer) and the Machine Learning models.

**Step-by-Step Deployment:**
1. Go to [Render Dashboard](https://dashboard.render.com).
2. Click the **"New +"** button in the top right corner and select **Blueprint**.
3. Connect your GitHub account and select your `akshatatcodes/web_scanner` repository.
4. Render will automatically detect the `render.yaml` configuration file we prepared.
5. A setup screen will appear asking you to fill in your **Environment Variables**:
   * **MONGO_URI**: Paste the MongoDB string you prepared in Part 1.
   * **REDIS_URI**: Paste the `rediss://` Upstash string you prepared in Part 1.
   * **GEMINI_API_KEY**: Paste your Google Gemini API key here.
   * **OPENAI_API_KEY**: Paste your OpenAI API key here.
6. Click **Apply / Deploy**.
7. Render will now build your custom Docker container. This will take a few minutes as it installs Google Chrome dependencies.
8. Once the build finishes and the log says `Web Security Exposure Analyzer backend running on http://localhost:5000` and `[Database] Connected`, **COPY the live URL Render gives you** at the top of the screen (e.g., `https://web-scanner-backend.onrender.com`).

---

## Part 3: Deploying the Frontend (Vercel.com)

The frontend is the sleek, professional UI dashboard written in React. It needs to know how to securely communicate with the Render backend we just created.

**Step-by-Step Deployment:**
1. Go to [Vercel Dashboard](https://vercel.com/dashboard).
2. Click **"Add New..."** -> **Project**.
3. Link your GitHub account and import the `akshatatcodes/web_scanner` repository.
4. Vercel will automatically detect that it's a Vite/React project.
5. **CRITICAL STEP:** Before clicking "Deploy", expand the **"Environment Variables"** section.
   * **Name**: `VITE_API_BASE`
   * **Value**: Paste the Render URL you copied at the end of Part 2, and add `/api` to the end of it.  
     *(Example: `https://web-scanner-backend.onrender.com/api`)*
6. Click **Add**.
7. Finally, click **Deploy**.
8. Vercel will compile the React code and assign a live, global domain name (e.g., `https://web-scanner.vercel.app`). We've already configured `vercel.json`, so URL routing will work flawlessly out of the box.

---

🎊 **Congratulations!** Click the Vercel link when it's done. You now have a fully functional, globally distributed Security Engine scanning websites from the cloud!
