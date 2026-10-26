from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse
import ipaddress
import os
import joblib
import pandas as pd

app = Flask(__name__)
CORS(app)

# Load CyberNova model
MODEL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "cybernova_url_model.pkl"
)

model = joblib.load(MODEL_PATH)

print("\n===================================")
print("       CYBERNOVA STARTED")
print("===================================")
print("MODEL FEATURES:", list(model.feature_names_in_))
print("MODEL CLASSES:", list(model.classes_))


def analyze_url(url):
    url = url.strip()
    warnings = []

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        # Validate URL
        if parsed.scheme not in ("http", "https") or not hostname:
            return {
                "url": url,
                "status": "Invalid URL",
                "message": "Enter a valid URL starting with http:// or https://",
                "warnings": [],
                "notice": "Enter a valid URL to continue."
            }

        hostname = hostname.lower()

        # 1. IP address
        try:
            ipaddress.ip_address(hostname)
            has_ip = -1
            warnings.append(
                "URL uses an IP address instead of a domain name."
            )
        except ValueError:
            has_ip = 1

        # 2. URL length
        if len(url) < 54:
            url_length = -1
        elif len(url) <= 75:
            url_length = 0
        else:
            url_length = 1

        # 3. URL shortening service
        shortening_services = [
            "bit.ly", "tinyurl.com", "t.co", "goo.gl",
            "is.gd", "buff.ly", "ow.ly", "shorturl.at"
        ]

        is_shortened = -1 if any(
            hostname == service or
            hostname.endswith("." + service)
            for service in shortening_services
        ) else 1

        if is_shortened == -1:
            warnings.append(
                "URL uses a known shortening service."
            )

        # 4. @ symbol
        has_at = -1 if "@" in url else 1

        if has_at == -1:
            warnings.append("URL contains an @ symbol.")

        # 5. Additional double slash
        after_domain = url.split("://", 1)[-1]
        double_slash = -1 if "//" in after_domain else 1

        if double_slash == -1:
            warnings.append(
                "URL contains an additional double slash."
            )

        # 6. Hyphen in hostname
        prefix_suffix = -1 if "-" in hostname else 1

        if prefix_suffix == -1:
            warnings.append("Domain contains a hyphen.")

        # 7. Subdomain count
        parts = hostname.split(".")
        subdomain_count = max(0, len(parts) - 2)

        if subdomain_count == 0:
            subdomain_feature = -1
        elif subdomain_count == 1:
            subdomain_feature = 0
        else:
            subdomain_feature = 1
            warnings.append(
                "Domain has multiple subdomain parts."
            )

        # 8. HTTPS token in hostname
        https_token = -1 if "https" in hostname else 1

        # Feature values
        feature_values = {
            "having_IP_Address": has_ip,
            "URL_Length": url_length,
            "Shortining_Service": is_shortened,
            "having_At_Symbol": has_at,
            "double_slash_redirecting": double_slash,
            "Prefix_Suffix": prefix_suffix,
            "having_Sub_Domain": subdomain_feature,
            "HTTPS_token": https_token
        }

        # Match the model's feature order
        feature_names = list(model.feature_names_in_)

        features = pd.DataFrame(
            [[feature_values[name] for name in feature_names]],
            columns=feature_names
        )

        # Predict
        prediction = int(model.predict(features)[0])
        probabilities = model.predict_proba(features)[0]
        classes = list(model.classes_)

        # Log every scan in the terminal
        print("\n========== CYBERNOVA SCAN ==========")
        print("URL:", url)
        print("FEATURES:", feature_values)
        print("MODEL CLASSES:", classes)
        print("MODEL PREDICTION:", prediction)
        print("MODEL PROBABILITIES:", probabilities)

        # This mapping must match the training dataset labels.
        # Assumption: -1 = phishing, 1 = legitimate.
        phishing_probability = None

        if -1 in classes:
            phishing_index = classes.index(-1)
            phishing_probability = round(
                float(probabilities[phishing_index]) * 100, 2
            )

        print(
            "PHISHING PROBABILITY (%):",
            phishing_probability
        )
        print("====================================\n", flush=True)

        # Classification
        if prediction == -1:
            status = "Potential Phishing"
            message = (
                "The model classified this URL as potentially "
                "suspicious. Avoid entering sensitive information "
                "until the website has been independently verified."
            )
        else:
            status = "No Obvious Warning Found"
            message = (
                "The model did not classify this URL as phishing. "
                "This does not guarantee the website is safe."
            )

        return {
            "url": url,
            "status": status,
            "message": message,
            "warnings": warnings,
            "model_prediction": prediction,
            "model_classes": [int(c) for c in classes],
            "phishing_probability_percent": phishing_probability,
            "notice": (
                "Prototype result only. Model predictions may be "
                "incorrect and cannot guarantee website safety."
            )
        }

    except Exception as error:
        print("ANALYSIS ERROR:", repr(error), flush=True)

        return {
            "url": url,
            "status": "Analysis Error",
            "message": (
                "Unable to analyze this URL. "
                "Check the backend terminal for details."
            ),
            "warnings": [],
            "notice": "Prototype result only."
        }


@app.route("/")
def home():
    return "<h1>CyberNova Backend Running!</h1>"


@app.route("/analyze", methods=["POST"])
def analyze():
    print("SCAN REQUEST RECEIVED!", flush=True)

    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    if not isinstance(url, str) or not url.strip():
        return jsonify({
            "url": "",
            "status": "Invalid URL",
            "message": "Please enter a website URL.",
            "warnings": []
        }), 400

    result = analyze_url(url)

    print("SCAN RESULT:", result.get("status"), flush=True)

    return jsonify(result)


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )
