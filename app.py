from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
import json
import re
import requests
import pandas as pd
from urllib.parse import urlparse
from datetime import datetime
import ssl
import socket
import whois
import base64
import os
from sklearn.ensemble import RandomForestClassifier

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_FEATURE_NAMES = [
    'url_length', 'num_dots', 'num_slashes', 'num_question_marks', 'num_equals',
    'num_hyphens', 'num_underscores', 'num_keywords', 'num_digits', 'num_letters',
    'hostname_length', 'num_subdomains', 'has_ip', 'num_dots_hostname', 'path_length',
    'num_slashes_path', 'num_percent', 'num_at', 'num_double_slash', 'tld_length',
    'is_common_tld', 'digit_ratio', 'letter_ratio', 'special_char_ratio',
    'feature_24', 'feature_25', 'feature_26', 'feature_27', 'feature_28', 'feature_29'
]

MODEL_CANDIDATES = [
    os.path.join(BASE_DIR, 'model', 'phishing_model.pkl'),
    os.path.join(BASE_DIR, 'phishing_model.pkl'),
]
CONFIG_CANDIDATES = [
    os.path.join(BASE_DIR, 'model', 'feature_config.json'),
    os.path.join(BASE_DIR, 'feature_config.json'),
]


def extract_features(url):
    """Extract 30 features from URL (matching UCI dataset)"""
    features = {}
    parsed = urlparse(url)

    # Basic URL features
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_slashes'] = url.count('/')
    features['num_question_marks'] = url.count('?')
    features['num_equals'] = url.count('=')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_keywords'] = sum(1 for kw in ['login', 'signin', 'secure', 'account', 'verify'] if kw in url.lower())
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_letters'] = sum(c.isalpha() for c in url)

    # Host features
    hostname = parsed.netloc
    features['hostname_length'] = len(hostname)
    features['num_subdomains'] = hostname.count('.') + 1 if hostname else 0
    features['has_ip'] = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname) else 0
    features['num_dots_hostname'] = hostname.count('.')

    # Path features
    path = parsed.path
    features['path_length'] = len(path)
    features['num_slashes_path'] = path.count('/')

    # Special characters
    features['num_percent'] = url.count('%')
    features['num_at'] = url.count('@')
    features['num_double_slash'] = 1 if '//' in url else 0

    # TLD features
    tld = url.split('.')[-1].split('/')[0] if '.' in url else ''
    features['tld_length'] = len(tld)
    features['is_common_tld'] = 1 if tld in ['com', 'org', 'net', 'edu', 'gov'] else 0

    # Advanced features
    features['digit_ratio'] = features['num_digits'] / (features['url_length'] + 1)
    features['letter_ratio'] = features['num_letters'] / (features['url_length'] + 1)
    features['special_char_ratio'] = (features['num_dots'] + features['num_slashes'] + features['num_hyphens']) / (features['url_length'] + 1)

    for fname in DEFAULT_FEATURE_NAMES:
        if fname not in features:
            features[fname] = 0

    return [features.get(fname, 0) for fname in DEFAULT_FEATURE_NAMES]


def train_default_model():
    """Train a fresh RandomForest model to match the app's feature extractor."""
    dataset_candidates = [
        os.path.join(BASE_DIR, 'balanced_urls.csv'),
        os.path.join(BASE_DIR, 'Dataset.csv'),
        os.path.join(BASE_DIR, 'dataset_phishing.csv'),
        os.path.join(BASE_DIR, 'phishing_clean.csv'),
        os.path.join(BASE_DIR, 'phishing_urls.csv'),
        os.path.join(BASE_DIR, 'urlhaus_cleaned1.csv'),
        os.path.join(BASE_DIR, 'legitimate_urls.csv'),
    ]

    dataset_path = next((p for p in dataset_candidates if os.path.exists(p)), None)
    if dataset_path is None:
        raise FileNotFoundError('No usable training dataset was found in the project root.')

    df = pd.read_csv(dataset_path)
    if 'url' not in df.columns:
        raise ValueError(f'Dataset {dataset_path} does not contain a URL column.')

    label_col = None
    for candidate in ['label', 'Result', 'class', 'phishing', 'target', 'Label']:
        if candidate in df.columns:
            label_col = candidate
            break

    if label_col is None:
        raise ValueError(f'Dataset {dataset_path} does not contain a recognizable target label column.')

    filtered = df[[label_col, 'url']].dropna().copy()
    filtered[label_col] = filtered[label_col].astype(str).str.strip().str.lower()
    filtered['label'] = filtered[label_col].map({
        'phishing': 1,
        'malicious': 1,
        '1': 1,
        'yes': 1,
        'legitimate': 0,
        'safe': 0,
        '0': 0,
        'no': 0,
    })
    filtered = filtered.dropna(subset=['label'])  # type: ignore[call-arg]

    if filtered.empty:
        raise ValueError('No usable rows remained after label normalization.')

    X = np.array([extract_features(url) for url in filtered['url']], dtype=float)
    y = filtered['label'].astype(int).to_numpy()

    model = RandomForestClassifier(n_estimators=200, random_state=42, class_weight='balanced')
    model.fit(X, y)

    save_path = os.path.join(BASE_DIR, 'model', 'phishing_model.pkl')
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    joblib.dump(model, save_path)

    config_path = os.path.join(BASE_DIR, 'model', 'feature_config.json')
    with open(config_path, 'w') as f:
        json.dump({'feature_names': DEFAULT_FEATURE_NAMES, 'model_type': 'RandomForest'}, f, indent=2)

    return model


# Load model and config
model = None
feature_names = DEFAULT_FEATURE_NAMES.copy()
config = {}

for model_path in MODEL_CANDIDATES:
    if os.path.exists(model_path):
        try:
            model = joblib.load(model_path)
            print(f"Loaded model from {model_path}")
            break
        except Exception as e:
            print(f"Skipping incompatible model at {model_path}: {e}")

if model is None:
    try:
        model = train_default_model()
        print('Trained fresh phishing detector model.')
    except Exception as e:
        print(f"Error training model: {e}")
        model = None

for config_path in CONFIG_CANDIDATES:
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            feature_names = config.get('feature_names', DEFAULT_FEATURE_NAMES)
            break
        except Exception as e:
            print(f"Error loading config from {config_path}: {e}")

if model is None or not feature_names:
    print("Error loading model: model or feature configuration not found.")
    print("Please run 'python model/train_model.py' first")

VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '06d82c85ea5910007ce41823d0709b980a99b6cff77aaceafcd0ee9d52a6c410')

def get_domain_age(domain):
    """Get domain age using WHOIS"""
    try:
        w = whois.whois(domain)
        if isinstance(w, dict):
            creation_date = w.get('creation_date')
        else:
            creation_date = getattr(w, 'creation_date', None)

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return {
                'age_days': age_days,
                'creation_date': creation_date.strftime('%Y-%m-%d'),
                'is_new': age_days < 30
            }
    except Exception:
        pass

    return {
        'age_days': None,
        'creation_date': 'Unknown',
        'is_new': False
    }

def check_ssl_certificate(domain):
    """Check SSL certificate validity"""
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket())
        conn.settimeout(5)
        conn.connect((domain, 443))
        cert = conn.getpeercert()

        if not cert:
            raise ValueError('No certificate found')

        not_before = datetime.strptime(str(cert.get('notBefore', '')), '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(str(cert.get('notAfter', '')), '%b %d %H:%M:%S %Y %Z')

        days_until_expiry = (not_after - datetime.now()).days

        issuer = cert.get('issuer') or ()
        issuer_name = issuer[0][0][1] if issuer and issuer[0] and issuer[0][0] else 'Unknown'

        return {
            'valid': True,
            'issuer': issuer_name,
            'expires': not_after.strftime('%Y-%m-%d'),
            'days_until_expiry': days_until_expiry,
            'is_expiring_soon': days_until_expiry < 30
        }
    except Exception:
        return {
            'valid': False,
            'issuer': 'None',
            'expires': 'N/A',
            'days_until_expiry': 0,
            'is_expiring_soon': True
        }

def check_virustotal(url):
    """Check URL reputation using VirusTotal API."""
    default_api_key = '06d82c85ea5910007ce41823d0709b980a99b6cff77aaceafcd0ee9d52a6c410'
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == default_api_key:
        return {
            'available': False,
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0,
            'is_malicious': False,
            'message': 'VirusTotal API key not configured. Using local checks only.'
        }

    try:
        response = requests.post(
            'https://www.virustotal.com/api/v3/urls',
            data={'url': url},
            headers={'x-apikey': VIRUSTOTAL_API_KEY},
            timeout=10,
        )
        if response.status_code != 200:
            raise ValueError(f'VirusTotal request failed: {response.status_code}')

        analysis_id = response.json().get('data', {}).get('id')
        if not analysis_id:
            raise ValueError('VirusTotal did not return an analysis id.')

        result = requests.get(
            f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
            headers={'x-apikey': VIRUSTOTAL_API_KEY},
            timeout=10,
        )
        result.raise_for_status()
        stats = result.json().get('data', {}).get('attributes', {}).get('stats', {})
        malicious = int(stats.get('malicious', 0))
        suspicious = int(stats.get('suspicious', 0))
        harmless = int(stats.get('harmless', 0))

        return {
            'available': True,
            'malicious': malicious,
            'suspicious': suspicious,
            'harmless': harmless,
            'is_malicious': malicious > 0 or suspicious > 0,
            'message': 'VirusTotal check completed.'
        }
    except Exception:
        return {
            'available': False,
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0,
            'is_malicious': False,
            'message': 'VirusTotal check unavailable at the moment.'
        }


def get_top_features(url):
    """Return a short list of the strongest suspicious indicators."""
    values = extract_features(url)
    ranked = sorted(zip(feature_names, values), key=lambda item: abs(float(item[1])), reverse=True)
    top = []
    for name, value in ranked[:5]:
        if name == 'url_length':
            label = 'URL length'
        elif name == 'num_subdomains':
            label = 'Subdomain count'
        elif name == 'num_keywords':
            label = 'Keyword count'
        elif name == 'num_dots_hostname':
            label = 'Domain dot count'
        else:
            label = name.replace('_', ' ')
        top.append(f'{label}: {value}')
    return top


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict_url():
    data = request.get_json(silent=True) or {}
    raw_url = str(data.get('url', '')).strip()

    if not raw_url:
        return jsonify({'error': 'Please provide a valid URL.'}), 400

    url = raw_url if re.match(r'^(https?|ftp)://', raw_url, re.IGNORECASE) else f'http://{raw_url}'
    parsed = urlparse(url)
    hostname = parsed.hostname or parsed.netloc

    if not hostname:
        return jsonify({'error': 'Invalid URL format. Please enter a proper website address.'}), 400

    if model is None:
        return jsonify({'error': 'Model not loaded. Please train the model first.'}), 500

    feature_vector = np.array(extract_features(url), dtype=float).reshape(1, -1)
    probability = float(model.predict_proba(feature_vector)[0, 1])
    ml_risk_score = int(round(probability * 100))

    domain = hostname.split(':')[0]
    domain_info = get_domain_age(domain)
    ssl_info = check_ssl_certificate(domain)
    virustotal_info = check_virustotal(url)

    risk_factors = []
    if ml_risk_score >= 70:
        risk_factors.append('High machine learning risk score')
    if url.count('.') > 4 or hostname.count('.') > 2:
        risk_factors.append('Multiple subdomains or suspicious domain structure')
    if 'login' in url.lower() or 'verify' in url.lower() or 'secure' in url.lower():
        risk_factors.append('Phishing keywords detected')
    if not ssl_info['valid']:
        risk_factors.append('No valid SSL certificate')
    if domain_info.get('is_new'):
        risk_factors.append('Very new domain registration')
    if virustotal_info.get('is_malicious'):
        risk_factors.append('Flagged by threat intelligence sources')

    if not risk_factors:
        risk_factors = ['No major suspicious indicators detected']

    risk_score = ml_risk_score
    risk_score += 15 if not ssl_info['valid'] else 0
    risk_score += 20 if domain_info.get('is_new') else 0
    risk_score += virustotal_info.get('malicious', 0) * 10
    risk_score += virustotal_info.get('suspicious', 0) * 5
    risk_score = max(0, min(100, risk_score))

    if risk_score >= 70:
        label = 'Phishing'
    elif risk_score >= 40:
        label = 'Suspicious'
    else:
        label = 'Legitimate'

    return jsonify({
        'label': label,
        'risk_score': risk_score,
        'ml_risk_score': ml_risk_score,
        'risk_factors': risk_factors[:5],
        'top_features': get_top_features(url),
        'domain_info': domain_info,
        'ssl_info': ssl_info,
        'virustotal_info': virustotal_info,
    })


if __name__ == '__main__':
    app.run(debug=True)