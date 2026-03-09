const axios = require('axios');
const fs = require('fs');
const path = require('path');

const BASE_URL = 'https://raw.githubusercontent.com/dochne/wappalyzer/master/src';
const RULES_DIR = path.join(__dirname, 'rules');
const TECH_DIR = path.join(RULES_DIR, 'technologies');

async function download() {
    console.log('Starting rules download...');

    if (!fs.existsSync(TECH_DIR)) fs.mkdirSync(TECH_DIR, { recursive: true });

    // 1. Download Categories
    try {
        console.log('Downloading categories.json...');
        const catRes = await axios.get(`${BASE_URL}/categories.json`);
        fs.writeFileSync(path.join(RULES_DIR, 'categories.json'), JSON.stringify(catRes.data, null, 2));
    } catch (e) {
        console.error('Failed to download categories:', e.message);
    }

    // 2. Download a-z and _
    const letters = 'abcdefghijklmnopqrstuvwxyz_'.split('');
    const allTechnologies = {};

    for (const char of letters) {
        const fileName = `${char}.json`;
        const url = `${BASE_URL}/technologies/${fileName}`;
        console.log(`Downloading ${fileName}...`);

        try {
            const res = await axios.get(url);
            fs.writeFileSync(path.join(TECH_DIR, fileName), JSON.stringify(res.data, null, 2));
            Object.assign(allTechnologies, res.data);
            console.log(`  Added ${Object.keys(res.data).length} technologies from ${fileName}`);
        } catch (e) {
            console.error(`  Failed to download ${fileName}:`, e.message);
        }
    }

    // 3. Write merged rules
    console.log(`Total technologies collected: ${Object.keys(allTechnologies).length}`);
    fs.writeFileSync(path.join(RULES_DIR, 'technologies.json'), JSON.stringify(allTechnologies, null, 2));

    // Create categories mapping file
    const catData = JSON.parse(fs.readFileSync(path.join(RULES_DIR, 'categories.json'), 'utf8'));
    const catMap = "module.exports = " + JSON.stringify(catData, null, 2) + ";";
    fs.writeFileSync(path.join(RULES_DIR, 'categories.js'), catMap);

    // Create technologies module
    const techModule = "module.exports = " + JSON.stringify(allTechnologies, null, 2) + ";";
    fs.writeFileSync(path.join(RULES_DIR, 'technologies.js'), techModule);

    console.log('Rules integrated successfully!');
}

download();
