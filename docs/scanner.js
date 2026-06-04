const websiteScanBtn = document.getElementById("websiteScanBtn");
const websiteUrlInput = document.getElementById("websiteUrlInput");
const websiteResult = document.getElementById("websiteResult");
const websiteHistory = document.getElementById("websiteHistory");

function getWebsiteHistory() {
    return JSON.parse(localStorage.getItem("websiteScanHistory")) || [];
}

function saveWebsiteHistory(url, status) {
    let history = getWebsiteHistory();

    history.unshift({
        url: url,
        status: status,
        date: new Date().toLocaleString()
    });

    history = history.slice(0, 5);

    localStorage.setItem("websiteScanHistory", JSON.stringify(history));
    loadWebsiteHistory();
}

function loadWebsiteHistory() {
    const history = getWebsiteHistory();

    websiteHistory.innerHTML = "";

    if (history.length === 0) {
        websiteHistory.innerHTML = "<li>No scans yet.</li>";
        return;
    }

    history.forEach(scan => {
        const li = document.createElement("li");
        li.innerHTML = `
            <strong>${scan.status}</strong><br>
            <span>${scan.url}</span><br>
            <small>${scan.date}</small>
        `;
        websiteHistory.appendChild(li);
    });
}

websiteScanBtn.addEventListener("click", function () {
    const url = websiteUrlInput.value.trim().toLowerCase();

    if (!url) {
        websiteResult.innerHTML = "Please enter a link.";
        websiteResult.style.color = "orange";
        return;
    }

    const suspiciousPatterns = [
        ".xyz",
        ".tk",
        ".ru",
        "bit.ly",
        "free-money",
        "verify-account",
        "login-now",
        "claim-now",
        "scholarship",
        "password-reset",
        "account-locked",
        "update-billing",
        "security-alert",
        "bank-login"
    ];

    const isSuspicious = suspiciousPatterns.some(pattern =>
        url.includes(pattern)
    );

    if (isSuspicious) {
        websiteResult.innerHTML = "⚠ Suspicious link detected!";
        websiteResult.style.color = "red";
        saveWebsiteHistory(url, "Suspicious");
    } else {
        websiteResult.innerHTML = "✅ Link appears safe.";
        websiteResult.style.color = "limegreen";
        saveWebsiteHistory(url, "Safe");
    }
});

loadWebsiteHistory();