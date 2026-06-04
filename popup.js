const scanBtn = document.getElementById("scanBtn");
const reportBtn = document.getElementById("reportBtn");
const result = document.getElementById("result");
const linkInput = document.getElementById("linkInput");
const historyList = document.getElementById("historyList");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");

reportBtn.style.display = "none";

scanBtn.addEventListener("click", async function () {
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
        ".xyz", ".tk", ".ru", "bit.ly",
        "free-money", "verify-account",
        "login-now", "claim-now", "scholarship"
    ];

    const isSuspicious = suspiciousPatterns.some(pattern =>
        url.includes(pattern)
    );

    if (isSuspicious) {
        result.innerHTML = "Suspicious link detected!";
        result.style.color = "red";
        reportBtn.style.display = "block";
        saveToHistory(url, "Suspicious");
        return;
    }

    result.innerHTML = "Link appears safe.";
    result.style.color = "green";
    saveToHistory(url, "Safe");
});

reportBtn.addEventListener("click", function () {
    chrome.tabs.create({
        url: "https://safebrowsing.google.com/safebrowsing/report_phish/"
    });
});

function getHistory() {
    return JSON.parse(localStorage.getItem("scanHistory")) || [];
}

function saveToHistory(url, status) {
    const scan = {
        url: url,
        status: status,
        date: new Date().toLocaleString()
    };

    let history = getHistory();
    history.unshift(scan);

    if (history.length > 10) {
        history = history.slice(0, 10);
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

    history.forEach(scan => {
        const li = document.createElement("li");

        li.innerHTML = `
            <strong>${scan.status}</strong><br>
            <span>${scan.url}</span><br>
            <small>${scan.date}</small>
        `;

        historyList.appendChild(li);
    });
}

clearHistoryBtn.addEventListener("click", function () {
    localStorage.removeItem("scanHistory");
    loadHistory();
});

document.addEventListener("DOMContentLoaded", loadHistory);