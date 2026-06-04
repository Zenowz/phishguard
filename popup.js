const scanBtn = document.getElementById("scanBtn");
const reportBtn = document.getElementById("reportBtn");
const result = document.getElementById("result");
const linkInput = document.getElementById("linkInput");

scanBtn.addEventListener("click", async function () {
    const url = linkInput.value.trim().toLowerCase();

    reportBtn.style.display = "none";

    const apiKey = "AIzaSyBWxz1MnjqCvDAIZbAVuqtxrbptV6Y9GsY";

    if (!url) {
        result.innerHTML = "Please enter a link.";
        result.style.color = "orange";
        return;
    }

    result.innerHTML = "Scanning...";
    result.style.color = "blue";

    // Local heuristic detection
    const suspiciousPatterns = [
        ".xyz",
        ".tk",
        ".ru",
        "bit.ly",
        "free-money",
        "verify-account",
        "login-now",
        "claim-now",
        "scholarship"
    ];

    const isSuspicious = suspiciousPatterns.some(pattern =>
        url.includes(pattern)
    );

    if (isSuspicious) {
        result.innerHTML = "⚠ Suspicious link detected!";
        result.style.color = "red";
        reportBtn.style.display = "block";
        return;
    }

    // Google Safe Browsing API check
    const requestBody = {
        client: {
            clientId: "phishguard",
            clientVersion: "1.0"
        },
        threatInfo: {
            threatTypes: [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE"
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [
                {
                    url: url
                }
            ]
        }
    };

    try {
        const response = await fetch(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(requestBody)
            }
        );

        const data = await response.json();

        if (data.matches) {
            result.innerHTML = "Dangerous link found by Google Safe Browsing!";
            result.style.color = "red";
            reportBtn.style.display = "block";
        } else {
            result.innerHTML = "Link appears safe.";
            result.style.color = "green";
        }

    } catch (error) {
        console.error(error);
        result.innerHTML = "API Error. Using local scan only.";
        result.style.color = "orange";
    }
});

reportBtn.addEventListener("click", function () {
    chrome.tabs.create({
        url: "https://safebrowsing.google.com/safebrowsing/report_phish/"
    });
});