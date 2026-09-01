# 🛡️ Phishing URL Detector - Advanced Web Application

A real-time phishing website detection system that combines **Machine Learning**, **WHOIS domain analysis**, **SSL certificate validation**, and **VirusTotal threat intelligence** to identify malicious URLs.

## ✨ Features

### 🔍 Multi-Layer Detection
- **Machine Learning Model**: Random Forest classifier trained on UCI Phishing Websites Dataset (11,055 samples, 30 features)
- **WHOIS Domain Age Check**: Detects newly registered domains (< 30 days)
- **SSL Certificate Validation**: Verifies certificate validity and expiration
- **VirusTotal Integration**: Checks URL reputation against 70+ security vendors

### 📊 Risk Scoring
- **ML Risk Score**: Base prediction from machine learning model (0-100)
- **Adjusted Risk Score**: Enhanced score with additional security checks
- **Risk Factors**: Detailed explanation of why a URL is flagged

## 🏗️ Architecture
