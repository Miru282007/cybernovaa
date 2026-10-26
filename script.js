const button = document.getElementById("scanButton");
const input = document.getElementById("url");
const result = document.getElementById("result");

// Scan button click
button.addEventListener("click", async function () {
    const url = input.value.trim();

    result.className = "";
    result.replaceChildren();
    result.style.display = "block";

    // Check empty input
    if (!url) {
        showResult(
            "Invalid URL",
            "Please enter a website URL.",
            "error"
        );
        return;
    }

    // Check URL format
    if (!/^https?:\/\//i.test(url)) {
        showResult(
            "Invalid URL",
            "Enter a URL starting with http:// or https://",
            "error"
        );
        return;
    }

    // Start scanning
    button.disabled = true;
    button.textContent = "Scanning...";

    showResult(
        "Scanning Website...",
        "CyberNova is analysing the URL. Please wait.",
        "loading"
    );

    try {
        // Connect to Flask backend
        const response = await fetch(
            "http://127.0.0.1:5000/analyze",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    url: url
                })
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.message || "Request failed."
            );
        }

        // Set result style
        let type = "safe";

        if (data.status === "Potential Phishing") {
            type = "danger";
        } else if (
            data.status === "Invalid URL" ||
            data.status === "Analysis Error"
        ) {
            type = "error";
        }

        // Display main result
        showResult(
            data.status || "Scan Result",
            data.message ||
                "No additional information available.",
            type
        );

        // Display scanned URL
        const scannedUrl = document.createElement("p");
        scannedUrl.textContent =
            "Scanned URL: " + (data.url || url);
        result.appendChild(scannedUrl);

        // Display URL warnings
        if (
            Array.isArray(data.warnings) &&
            data.warnings.length > 0
        ) {
            const warningTitle =
                document.createElement("h3");

            warningTitle.textContent = "URL Warnings";
            result.appendChild(warningTitle);

            const list = document.createElement("ul");

            data.warnings.forEach(function (warning) {
                const item = document.createElement("li");
                item.textContent = warning;
                list.appendChild(item);
            });

            result.appendChild(list);
        }

        // Display estimated probability
        if (
            data.phishing_probability_percent != null
        ) {
            const probability =
                document.createElement("p");

            probability.textContent =
                "Model-estimated phishing probability: " +
                data.phishing_probability_percent + "%";

            result.appendChild(probability);
        }

        // Display safety notice
        const notice = document.createElement("p");
        notice.className = "result-notice";

        notice.textContent =
            data.notice ||
            "Prototype result only. Website safety is not guaranteed.";

        result.appendChild(notice);

    } catch (error) {
        console.error("CyberNova error:", error);

        showResult(
            "Connection Error",
            "Could not connect to the backend. " +
            "Make sure app.py is running at " +
            "http://127.0.0.1:5000 and try again.",
            "error"
        );

    } finally {
        // Enable button again
        button.disabled = false;
        button.textContent = "Scan Website";
    }
});


// Function to display results
function showResult(title, message, type) {
    result.replaceChildren();

    result.className = "result-" + type;
    result.style.display = "block";

    const heading = document.createElement("h2");
    heading.textContent = title;
    result.appendChild(heading);

    const paragraph = document.createElement("p");
    paragraph.textContent = message;
    result.appendChild(paragraph);
}
