from flask import Flask, render_template, request, session, redirect, url_for
import pickle
import requests
import io
from urllib.parse import urlparse, unquote

app = Flask(__name__)
# IMPORTANT: Set a secret key for session management
app.config['SECRET_KEY'] = 'a_very_secret_and_complex_key_for_flask_session_security' 

# --- Model URLs (REPLACE THESE WITH YOUR PUBLIC GITHUB RELEASE URLs) ---
# Use the direct raw download URL from your GitHub Release or other storage.
PHISHING_MODEL_URL = "https://github.com/erringexplorer267/Website-or-Weapon/releases/download/v1.0.0/phishing.pkl"
VECTORIZER_URL = "https://github.com/erringexplorer267/Website-or-Weapon/releases/download/v1.0.0/vectorizer.pkl"
# -----------------------------------------------------------------------

vector = None
model = None
MAX_HISTORY_ITEMS = 5

# Function to load the models from a URL
def load_model_from_url(url):
    print(f"Downloading model from: {url}")
    try:
        # Use requests to get the content of the file
        response = requests.get(url)
        response.raise_for_status() # Raise an error for bad status codes (4xx or 5xx)
        
        # Load the content directly from memory (io.BytesIO)
        return pickle.load(io.BytesIO(response.content))
    except Exception as e:
        print(f"Error loading model from URL {url}: {e}")
        return None

# Function to analyze and extract suspicious URL features for user education
def analyze_url(url):
    results = []
    
    # Use urlparse to break the URL into components
    parsed = urlparse(url)
    full_url = unquote(url) # Decode URL-encoded characters

    # 1. URL Length Check
    if len(full_url) > 75:
        results.append(f"**Long URL**: The URL is unusually long ({len(full_url)} characters). Phishers use long URLs to hide the real domain.")
    
    # 2. Presence of Suspicious Characters (@, //, etc.)
    if '@' in full_url:
        results.append("**Presence of '@' Symbol**: The '@' symbol is often used to embed credentials or confuse the browser about the true destination.")

    # 3. Multiple Subdomains or Hiding Domain
    # This checks for unusual characters used to hide the true host name
    if parsed.netloc.count('-') > 4 or parsed.netloc.count('.') > 3:
        results.append("**Complex Subdomains**: The domain structure is overly complex or uses many hyphens, a technique to confuse the user.")
    
    # 4. Presence of IP Address (less common but suspicious)
    # Check if the network location (netloc) starts with digits (looks like an IP)
    host_is_ip = parsed.netloc.replace('.', '').replace(':', '').isdigit()
    if host_is_ip:
         results.append("**IP Address Used**: Using an explicit IP address instead of a domain name is highly suspicious for legitimate sites.")
          
    # 5. Keywords in Path (Phishing tactics like 'login', 'verify')
    suspicious_keywords = ['login', 'verify', 'update', 'banking', 'secure']
    path_lower = parsed.path.lower()
    for keyword in suspicious_keywords:
        if keyword in path_lower and keyword not in parsed.netloc.lower():
            results.append(f"**Suspicious Path Keyword**: The URL path contains '{keyword}', a common tactic used by phishing sites to trick victims.")
            break # only list one keyword finding

    return results

# Load models once when the app starts
try:
    vector = load_model_from_url(VECTORIZER_URL)
    model = load_model_from_url(PHISHING_MODEL_URL)
except Exception as e:
    print(f"Fatal error during initial model loading: {e}")


@app.route("/", methods=['GET', 'POST'])
def index():
    
    # Use session.pop() to retrieve temporary results from the last POST request (PRG pattern)
    predict_message = session.pop('predict_message', None)
    predict_class = session.pop('predict_class', None)
    url_checked = session.pop('url_checked', None)
    analysis_results = session.pop('analysis_results', None)
    

    # Pre-check for model loading errors
    if vector is None or model is None:
        if predict_message is None:
            predict_message = "System Error: Model files could not be loaded from storage. Check logs and model URLs."
            predict_class = 'error'
        # Render the template with the error message
        return render_template("index.html", predict_message=predict_message, predict_class=predict_class)
        
    if request.method == "POST":
        url = request.form.get('url')
        
        if not url:
            session['predict_message'] = "Please submit a URL to check."
            session['predict_class'] = 'error'
            return redirect(url_for('index')) # Redirect after POST
            
        url_checked = url # Store the URL for display

        try:
            # Predict the class (e.g., 'good' or 'bad')
            predict_result = model.predict(vector.transform([url]))[0]
            
            # --- Set Prediction Message and Class and Analysis ---
            if predict_result == 'bad':
                predict_message = "🔴 DANGER: PHISHING DETECTED! This site exhibits characteristics commonly associated with malicious links. Do not proceed."
                predict_class = 'bad'
                # IMPLEMENT MEDIUM FEATURE: Run Analysis when flagged as BAD
                analysis_results = analyze_url(url)
            elif predict_result == 'good':
                predict_message = "✅ SAFE: This URL appears legitimate and is likely safe to visit."
                predict_class = 'good'
                analysis_results = None # No need for analysis on good result
            else:
                predict_message = "Error in prediction. Please try again. ❓"
                predict_class = 'error'
                analysis_results = None
            
            # 1. Save prediction results temporarily to session for the immediate GET request (PRG)
            session['predict_message'] = predict_message
            session['predict_class'] = predict_class
            session['url_checked'] = url_checked
            session['analysis_results'] = analysis_results if analysis_results is not None else []

            # 2. Add to history (Easy Feature: History Log)
            if 'history' not in session:
                session['history'] = []
            
            # Add the new entry to the start of the list and trim
            session['history'].insert(0, {'url': url, 'result': predict_class})
            session['history'] = session['history'][:MAX_HISTORY_ITEMS]
            session.modified = True
            
            # 3. Use POST-REDIRECT-GET pattern
            return redirect(url_for('index'))
            
        except Exception as e:
            print(f"Prediction error: {e}")
            predict_message = f"An unexpected error occurred during the prediction process: {e.__class__.__name__}. 🛑"
            predict_class = 'error'
            
            # Save error message to session before redirect
            session['predict_message'] = predict_message
            session['predict_class'] = predict_class
            session['url_checked'] = url_checked
            session['analysis_results'] = []
            return redirect(url_for('index')) 

    else: # GET request (Handles initial load and the redirect from POST)
        return render_template("index.html", 
                               predict_message=predict_message, 
                               predict_class=predict_class,
                               url_checked=url_checked,
                               analysis_results=analysis_results)

if __name__ == "__main__":
    app.run(debug=True)
