from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import requests
import io
from urllib.parse import urlparse, unquote

# --------------------------------------------------------------------------------
# --- Configuration & Model Loading (UNCHANGED) ---
# --------------------------------------------------------------------------------

app = Flask(__name__)
# IMPORTANT: Enable CORS for all routes/origins
CORS(app)

# --- Model URLs (UNCHANGED) ---
PHISHING_MODEL_URL = "https://github.com/erringexplorer267/Website-or-Weapon/releases/download/v1.0.0/phishing.pkl"
VECTORIZER_URL = "https://github.com/erringexplorer267/Website-or-Weapon/releases/download/v1.0.0/vectorizer.pkl"

vector = None
model = None

# Function to load the models from a URL (UNCHANGED)
def load_model_from_url(url):
    print(f"Downloading model from: {url}")
    try:
        response = requests.get(url)
        response.raise_for_status()
        return pickle.load(io.BytesIO(response.content))
    except Exception as e:
        print(f"Error loading model from URL {url}: {e}")
        return None

# Function to analyze and extract suspicious URL features (UNCHANGED)
def analyze_url(url):
    results = []
    parsed = urlparse(url)
    full_url = unquote(url)

    # 1. URL Length Check
    if len(full_url) > 75:
        results.append(f"**Long URL**: The URL is unusually long ({len(full_url)} characters). Phishers use long URLs to hide the real domain.")
    
    # 2. Presence of Suspicious Characters (@, //, etc.)
    if '@' in full_url:
        results.append("**Presence of '@' Symbol**: The '@' symbol is often used to embed credentials or confuse the browser about the true destination.")

    # 3. Multiple Subdomains or Hiding Domain
    if parsed.netloc.count('-') > 4 or parsed.netloc.count('.') > 3:
        results.append("**Complex Subdomains**: The domain structure is overly complex or uses many hyphens, a technique to confuse the user.")
    
    # 4. Presence of IP Address (less common but suspicious)
    host_is_ip = parsed.netloc.replace('.', '').replace(':', '').isdigit()
    if host_is_ip:
         results.append("**IP Address Used**: Using an explicit IP address instead of a domain name is highly suspicious for legitimate sites.")
             
    # 5. Keywords in Path (Phishing tactics like 'login', 'verify')
    suspicious_keywords = ['login', 'verify', 'update', 'banking', 'secure']
    path_lower = parsed.path.lower()
    for keyword in suspicious_keywords:
        if keyword in path_lower and keyword not in parsed.netloc.lower():
            results.append(f"**Suspicious Path Keyword**: The URL path contains '{keyword}', a common tactic used by phishing sites to trick victims.")
            break 
    return results

# Load models once when the app starts
try:
    vector = load_model_from_url(VECTORIZER_URL)
    model = load_model_from_url(PHISHING_MODEL_URL)
except Exception as e:
    print(f"Fatal error during initial model loading: {e}")

# --------------------------------------------------------------------------------
# --- API ENDPOINTS ---
# --------------------------------------------------------------------------------

# NEW: Root Route for API Status Check
@app.route("/", methods=['GET'])
def home():
    """Returns a simple status message for the base URL."""
    model_status = "Loaded" if model is not None and vector is not None else "Error (Check Logs)"
    return jsonify({
        "service": "Phishing Detection API is Live",
        "api_status": "Operational",
        "model_status": model_status,
        "primary_endpoint": "/predict (POST)",
        "instruction": "Send a JSON body with a 'url' key to the /predict endpoint."
    }), 200


@app.route("/predict", methods=['POST'])
def predict_url():
    """Handles a POST request from the Chrome extension."""

    # 1. Check for model loading errors
    if vector is None or model is None:
        return jsonify({
            "status": "error",
            "message": "System Error: Model files could not be loaded. Please check server logs."
        }), 500
        
    # 2. Parse request data
    try:
        data = request.get_json()
        url = data.get('url')
    except Exception:
        return jsonify({"status": "error", "message": "Invalid JSON format in request body."}), 400

    if not url:
        return jsonify({"status": "error", "message": "URL not found in request body."}), 400

    # 3. Predict the class
    try:
        predict_result = model.predict(vector.transform([url]))[0]
        
        # --- Prepare Response ---
        analysis_results = []
        if predict_result == 'bad':
            predict_message = "PHISHING DETECTED!"
            predict_class = 'bad'
            analysis_results = analyze_url(url)
        elif predict_result == 'good':
            predict_message = "SAFE TO VISIT"
            predict_class = 'good'
        else:
            predict_message = "Prediction Error"
            predict_class = 'error'

        # Return the result as a simple JSON object for the extension to consume
        return jsonify({
            "status": "success",
            "url": url,
            "prediction": predict_class, 
            "message": predict_message, 
            "analysis": analysis_results
        })
            
    except Exception as e:
        print(f"Prediction error: {e}")
        return jsonify({
            "status": "error",
            "message": f"An unexpected error occurred: {e.__class__.__name__}"
        }), 500


@app.route("/health", methods=['GET'])
def health_check():
    """Simple check to ensure the server is running and models are loaded."""
    model_status = "Loaded" if model is not None and vector is not None else "Error"
    return jsonify({
        "service": "Phishing Detection API",
        "model_status": model_status,
        "api_version": "1.0"
    })

# --------------------------------------------------------------------------------
# --- Run Application ---
# --------------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5000)