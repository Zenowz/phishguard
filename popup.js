console.log("PhishGuard Firebase popup loaded");

const firebaseConfig = {
    apiKey: "AIzaSyCqZM7z2LItso2fwXqtaK75YxWmF4lNIMg",
    projectId: "phishguard-d129b"
};

const authBox = document.getElementById("authBox");
const appBox = document.getElementById("appBox");
const emailInput = document.getElementById("emailInput");
const passwordInput = document.getElementById("passwordInput");
const loginBtn = document.getElementById("loginBtn");
const registerBtn = document.getElementById("registerBtn");
const logoutBtn = document.getElementById("logoutBtn");
const authMessage = document.getElementById("authMessage");
const userEmail = document.getElementById("userEmail");

const scanBtn = document.getElementById("scanBtn");
const reportBtn = document.getElementById("reportBtn");
const result = document.getElementById("result");
const linkInput = document.getElementById("linkInput");
const historyList = document.getElementById("historyList");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");

const totalScans = document.getElementById("totalScans");
const safeScans = document.getElementById("safeScans");
const suspiciousScans = document.getElementById("suspiciousScans");
const dangerousScans = document.getElementById("dangerousScans");

reportBtn.style.display = "none";

let currentUser = JSON.parse(localStorage.getItem("phishguardUser")) || null;

function showApp() {
    authBox.style.display = "none";
    appBox.style.display = "block";
    userEmail.innerHTML = "Logged in as: " + currentUser.email;
    loadFirestoreHistory();
}

function showAuth() {
    authBox.style.display = "block";
    appBox.style.display = "none";
}

if (currentUser) {
    showApp();
} else {
    showAuth();
}

async function registerUser(email, password) {
    const url = `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${firebaseConfig.apiKey}`;

    const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, returnSecureToken: true })
    });

    const data = await response.json();

    if (data.error) throw new Error(data.error.message);

    currentUser = {
        uid: data.localId,
        email: data.email,
        idToken: data.idToken
    };

    localStorage.setItem("phishguardUser", JSON.stringify(currentUser));
    await createUserDocument();
    showApp();
}

async function loginUser(email, password) {
    const url = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${firebaseConfig.apiKey}`;

    const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, returnSecureToken: true })
    });

    const data = await response.json();

    if (data.error) throw new Error(data.error.message);

    currentUser = {
        uid: data.localId,
        email: data.email,
        idToken: data.idToken
    };

    localStorage.setItem("phishguardUser", JSON.stringify(currentUser));
    showApp();
}

async function createUserDocument() {
    const url = `https://firestore.googleapis.com/v1/projects/${firebaseConfig.projectId}/databases/(default)/documents/users/${currentUser.uid}`;

    await fetch(url, {
        method: "PATCH",
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + currentUser.idToken
        },
        body: JSON.stringify({
            fields: {
                email: { stringValue: currentUser.email },
                createdAt: { timestampValue: new Date().toISOString() }
            }
        })
    });
}

loginBtn.addEventListener("click", async function () {
    try {
        authMessage.innerHTML = "Logging in...";
        await loginUser(emailInput.value.trim(), passwordInput.value.trim());
    } catch (error) {
        authMessage.innerHTML = error.message;
    }
});

registerBtn.addEventListener("click", async function () {
    try {
        authMessage.innerHTML = "Creating account...";
        await registerUser(emailInput.value.trim(), passwordInput.value.trim());
    } catch (error) {
        authMessage.innerHTML = error.message;
    }
});

logoutBtn.addEventListener("click", function () {
    localStorage.removeItem("phishguardUser");
    currentUser = null;
    showAuth();
});

function analyzeURL(url) {
    let indicators = [];
    let score = 0;

    const checks = [
        { pattern: ".xyz", label: "Suspicious top-level domain: .xyz", points: 25 },
        { pattern: ".tk", label: "Suspicious top-level domain: .tk", points: 25 },
        { pattern: ".ru", label: "Suspicious top-level domain: .ru", points: 20 },
        { pattern: "bit.ly", label: "Shortened URL detected", points: 20 },
        { pattern: "free-money", label: "Phishing keyword detected: free-money", points: 25 },
        { pattern: "verify-account", label: "Phishing keyword detected: verify-account", points: 30 },
        { pattern: "login-now", label: "Phishing keyword detected: login-now", points: 25 },
        { pattern: "claim-now", label: "Phishing keyword detected: claim-now", points: 25 },
        { pattern: "scholarship", label: "Sensitive lure keyword detected: scholarship", points: 15 },
        { pattern: "password-reset", label: "Credential-related keyword detected: password-reset", points: 25 },
        { pattern: "account-locked", label: "Urgency keyword detected: account-locked", points: 25 },
        { pattern: "update-billing", label: "Billing-related keyword detected: update-billing", points: 25 },
        { pattern: "security-alert", label: "Urgency keyword detected: security-alert", points: 20 },
        { pattern: "bank-login", label: "Banking-related keyword detected: bank-login", points: 30 }
    ];

    checks.forEach(function (check) {
        if (url.includes(check.pattern)) {
            indicators.push(check.label);
            score += check.points;
        }
    });

    if (!url.startsWith("https://")) {
        indicators.push("URL does not use HTTPS");
        score += 15;
    }

    score = Math.min(score, 100);

    let status = "Safe";
    if (score >= 70) status = "Dangerous";
    else if (score >= 30) status = "Suspicious";

    if (indicators.length === 0) {
        indicators.push("No suspicious URL pattern detected");
    }

    return { status, score, indicators };
}

async function checkGoogleSafeBrowsing(url) {
    try {
        const response = await fetch("http://localhost:3000/safe-browsing", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();
        console.log("Google Safe Browsing Result:", data);
        return data;

    } catch (error) {
        console.error("Google Safe Browsing check failed:", error);

        return {
            safeBrowsingStatus: "API Error",
            matches: []
        };
    }
}

async function getAIExplanation(url, status, indicators, score) {
    try {
        const response = await fetch("http://localhost:3000/explain", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url, status, indicators, score })
        });

        const data = await response.json();
        return data.explanation;
    } catch {
        return "AI explanation unavailable. Make sure the Gemini server is running.";
    }
}

async function saveScanToFirestore(scan) {
    const url = `https://firestore.googleapis.com/v1/projects/${firebaseConfig.projectId}/databases/(default)/documents/users/${currentUser.uid}/scans`;

    await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + currentUser.idToken
        },
        body: JSON.stringify({
            fields: {
                url: { stringValue: scan.url },
                status: { stringValue: scan.status },
                score: { integerValue: scan.score },
                explanation: { stringValue: scan.explanation },
                scannedAt: { timestampValue: new Date().toISOString() }
            }
        })
    });
    console.log("========== FIRESTORE ==========");
    console.log("Scan saved successfully:");
    console.log(scan);
    console.log("===============================");
}

async function loadFirestoreHistory() {
    const url = `https://firestore.googleapis.com/v1/projects/${firebaseConfig.projectId}/databases/(default)/documents/users/${currentUser.uid}/scans?pageSize=20`;

    historyList.innerHTML = "<li>Loading cloud history...</li>";

    const response = await fetch(url, {
        method: "GET",
        headers: {
            "Authorization": "Bearer " + currentUser.idToken
        }
    });

    const data = await response.json();
    const docs = data.documents || [];

    let scans = docs.map(function (doc) {
        const f = doc.fields;

        return {
            url: f.url?.stringValue || "",
            status: f.status?.stringValue || "",
            score: Number(f.score?.integerValue || 0),
            explanation: f.explanation?.stringValue || "",
            scannedAt: f.scannedAt?.timestampValue || ""
        };
    });

    scans.sort(function (a, b) {
        return new Date(b.scannedAt) - new Date(a.scannedAt);
    });

    renderHistory(scans);
    renderStats(scans);
}

function renderHistory(scans) {
    historyList.innerHTML = "";

    if (scans.length === 0) {
        historyList.innerHTML = "<li>No scans yet.</li>";
        return;
    }

    scans.slice(0, 5).forEach(function (scan) {
        const date = new Date(scan.scannedAt).toLocaleString();

        const li = document.createElement("li");
        li.innerHTML = `
            <strong>${scan.status} - ${scan.score}/100</strong>
            <span>${scan.url}</span>
            <small>${date}</small>
        `;

        historyList.appendChild(li);
    });
}

function renderStats(scans) {
    totalScans.innerHTML = scans.length;
    safeScans.innerHTML = scans.filter(s => s.status === "Safe").length;
    suspiciousScans.innerHTML = scans.filter(s => s.status === "Suspicious").length;
    dangerousScans.innerHTML = scans.filter(s => s.status === "Dangerous").length;
}

scanBtn.addEventListener("click", async function () {
    const url = linkInput.value.trim().toLowerCase();
    reportBtn.style.display = "none";

    if (!url) {
        result.innerHTML = "Please enter a link.";
        result.style.color = "orange";
        return;
    }

    result.innerHTML = "Scanning URL structure and Google Safe Browsing...";
    result.style.color = "blue";

    let analysis = analyzeURL(url);

    console.log("========================================");
    console.log("PHISHGUARD SCAN STARTED");
    console.log("Scanning URL:", url);
    console.log("Initial Analysis:", analysis);
    console.log("========================================");

    const safeBrowsingResult = await checkGoogleSafeBrowsing(url);

    console.log("========== GOOGLE SAFE BROWSING ==========");
    console.log(safeBrowsingResult);
    console.log("==========================================");

    if (safeBrowsingResult.safeBrowsingStatus === "Dangerous") {
        analysis.status = "Dangerous";
        analysis.score = 100;
        analysis.indicators.push("Google Safe Browsing detected this URL as a known threat");
    } else if (safeBrowsingResult.safeBrowsingStatus === "No Threat Found") {
        analysis.indicators.push("Google Safe Browsing result: No known threat found");
    } else {
        analysis.indicators.push("Google Safe Browsing API unavailable or returned an error");
    }

    const status = analysis.status;
    const score = analysis.score;
    const indicators = analysis.indicators;

    result.style.color = status === "Safe" ? "green" : "red";

    if (status !== "Safe") {
        reportBtn.style.display = "block";
    }

    result.innerHTML = `
        <strong>${status} Link</strong><br>
        Threat Score: ${score}/100<br><br>
        Generating AI explanation...
    `;

    const explanation = await getAIExplanation(url, status, indicators, score);

    console.log("============= FINAL RESULT =============");
    console.log("Threat Score:", score);
    console.log("Threat Status:", status);
    console.log("Indicators:", indicators);
    console.log("AI Explanation:");
    console.log(explanation);
    console.log("========================================");

    result.innerHTML = `
        <strong>${status} Link</strong><br>
        Threat Score: ${score}/100<br><br>
        <div class="ai-explanation">
            ${explanation.replace(/\n/g, "<br>")}
        </div>
    `;

    const scan = {
        url,
        status,
        score,
        explanation
    };

    await saveScanToFirestore(scan);
    await loadFirestoreHistory();
});

clearHistoryBtn.addEventListener("click", function () {
    historyList.innerHTML = "<li>Local display cleared. Cloud data is still saved.</li>";
});

reportBtn.addEventListener("click", function () {
    chrome.tabs.create({
        url: "https://safebrowsing.google.com/safebrowsing/report_phish/"
    });
});