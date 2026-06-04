const scanBtn = document.getElementById("scanBtn");
const reportBtn = document.getElementById("reportBtn");
const result = document.getElementById("result");
const linkInput = document.getElementById("linkInput");
const historyList = document.getElementById("historyList");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");

reportBtn.style.display = "none";

function getHistory() {
    const savedHistory = localStorage.getItem("scanHistory");

    if (savedHistory) {
        return JSON.parse(savedHistory);
    }

    return [];
}

function saveToHistory(url, status) {
    const scan = {
        url: url,
        status: status,
        date: new Date().toLocaleString()
    };

    let history = getHistory();

    history.unshift(scan);

    if (history.length > 5) {
        history = history.slice(0, 5);
    }

    localStorage.setItem("scanHistory", JSON.stringify(history));

    loadHistory();
}

function loadHistory() {
    const history = getHistory();

    historyList.innerHTML = "";

    if (history.length === 0) {
        historyList.innerHTML = "<li>No scans yet.</li>";
        return;
    }

    history.forEach(function (scan) {
        const li = document.createElement("li");

        li.innerHTML = `
            <strong>${scan.status}</strong>
            <span>${scan.url}</span>
            <small>${scan.date}</small>
        `;

        historyList.appendChild(li);
    });
}

scanBtn.addEventListener("click", function () {
    const url = linkInput.value.trim().toLowerCase();

    reportBtn.style.display = "none";

    if (!url) {
        result.innerHTML = "Please enter a link.";
        result.style.color = "orange";
        return;
    }

    result.innerHTML = "Scanning...";
    result.style.color = "blue";

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

    const isSuspicious = suspiciousPatterns.some(function (pattern) {
        return url.includes(pattern);
    });

    setTimeout(function () {
        if (isSuspicious) {
            result.innerHTML = "Suspicious link detected!";
            result.style.color = "red";
            reportBtn.style.display = "block";
            saveToHistory(url, "Suspicious");
        } else {
            result.innerHTML = "Link appears safe.";
            result.style.color = "green";
            saveToHistory(url, "Safe");
        }
    }, 300);
});

clearHistoryBtn.addEventListener("click", function () {
    localStorage.removeItem("scanHistory");
    loadHistory();
});

reportBtn.addEventListener("click", function () {
    chrome.tabs.create({
        url: "https://safebrowsing.google.com/safebrowsing/report_phish/"
    });
});

loadHistory();