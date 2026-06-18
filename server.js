const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const { GoogleGenAI } = require("@google/genai");

dotenv.config();

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// Check API Key
if (!process.env.GEMINI_API_KEY) {
    console.error("❌ GEMINI_API_KEY not found in .env");
    process.exit(1);
}

const ai = new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY
});

// Test Route
app.get("/", (req, res) => {
    res.send("✅ PhishGuard Gemini AI Server Running");
});

// AI Explanation Route
app.post("/explain", async (req, res) => {

    try {

        const {
            url,
            status,
            indicators
        } = req.body;

        const prompt = `
You are an AI cybersecurity assistant for PhishGuard.

Analyze the following URL scan.

URL:
${url}

Status:
${status}

Detected Indicators:
${indicators.join(", ")}

Write your response EXACTLY in this format.

Threat Level:
(HIGH / MEDIUM / LOW)

Threat Explanation:
(Explain why.)

Recommendation:
(Give simple cybersecurity advice for students.)

Keep the response under 120 words.
`;

        const response = await ai.models.generateContent({
            model: "gemini-2.5-flash",
            contents: prompt
        });

        res.json({
            explanation: response.text
        });

    } catch (err) {

        console.error(err);

        res.status(500).json({
            explanation:
                "Gemini AI could not generate an explanation."
        });

    }

});

app.listen(PORT, () => {
    console.log(`🚀 PhishGuard Gemini Server running at http://localhost:${PORT}`);
});