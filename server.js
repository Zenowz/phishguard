const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const { GoogleGenAI } = require("@google/genai");

dotenv.config();

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

if (!process.env.GEMINI_API_KEY) {
    console.error("❌ GEMINI_API_KEY not found.");
    process.exit(1);
}

if (!process.env.GOOGLE_SAFE_BROWSING_API_KEY) {
    console.error("❌ GOOGLE_SAFE_BROWSING_API_KEY not found.");
    process.exit(1);
}

const ai = new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY
});

function generateFallbackExplanation(url, status, indicators, score) {

    const level =
        score >= 70 ? "HIGH" :
        score >= 30 ? "MEDIUM" :
        "LOW";

    const recommendation =
        status === "Safe"
            ? "This link appears safe, but always verify websites before entering personal information."
            : "Avoid entering passwords or banking information. Visit the official website directly instead.";

    return `
Threat Level:
${level}

Threat Explanation:
This link was analyzed using PhishGuard's local detection engine. The result is ${status} with a threat score of ${score}/100. Detected indicators include: ${indicators.join(", ")}.

Recommendation:
${recommendation}
`;
}

async function checkSafeBrowsing(urlToCheck) {

    const endpoint =
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_BROWSING_API_KEY}`;

    const body = {
        client: {
            clientId: "phishguard",
            clientVersion: "1.0"
        },
        threatInfo: {
            threatTypes: [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            platformTypes: [
                "ANY_PLATFORM"
            ],
            threatEntryTypes: [
                "URL"
            ],
            threatEntries: [
                {
                    url: urlToCheck
                }
            ]
        }
    };

    const response = await fetch(endpoint, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(body)
    });

    const data = await response.json();

    console.log("========== GOOGLE SAFE BROWSING ==========");
    console.log(JSON.stringify(data, null, 2));
    console.log("==========================================");

    return data;
}

app.get("/", (req, res) => {
    res.send("PhishGuard Server running.");
});

app.post("/safe-browsing", async (req, res) => {

    try {

        const { url } = req.body;

        console.log("Checking Google Safe Browsing:", url);

        const data = await checkSafeBrowsing(url);

        const dangerous =
            data.matches &&
            data.matches.length > 0;

        res.json({
            safeBrowsingStatus:
                dangerous
                    ? "Dangerous"
                    : "No Threat Found",

            matches: data.matches || [],
            rawResponse: data
        });

    } catch (error) {

        console.error("SAFE BROWSING ERROR:");
        console.error(error);

        res.status(500).json({
            safeBrowsingStatus: "API Error",
            matches: [],
            error: error.message
        });

    }

});

app.get("/test-gemini", async (req, res) => {

    try {

        const response = await ai.models.generateContent({
            model: "gemini-2.0-flash",
            contents: "Say exactly: Gemini is working."
        });

        res.json({
            success: true,
            text: response.text
        });

    } catch (error) {

        console.error("TEST GEMINI ERROR:");
        console.error(error);

        res.status(500).json({
            success: false,
            error: error.message
        });

    }

});

app.post("/explain", async (req, res) => {

    const {
        url,
        status,
        indicators,
        score
    } = req.body;

    try {

        const prompt = `
You are PhishGuard.

URL:
${url}

Threat Status:
${status}

Threat Score:
${score}/100

Indicators:
${indicators.join(", ")}

Write EXACTLY using this format.

Threat Level:
HIGH, MEDIUM or LOW

Threat Explanation:
Explain in less than 80 words.

Recommendation:
Simple cybersecurity advice for students.
`;

        const response =
            await ai.models.generateContent({
                model: "gemini-2.0-flash",
                contents: prompt
            });

        res.json({
            explanation: response.text
        });

    } catch (error) {

        console.error("GEMINI ERROR:");
        console.error(error);

        res.json({
            explanation:
                generateFallbackExplanation(
                    url,
                    status,
                    indicators,
                    score
                )
        });

    }

});

app.listen(PORT, () => {

    console.log("=================================");
    console.log(`🚀 PhishGuard Server running`);
    console.log(`http://localhost:${PORT}`);
    console.log("=================================");

});