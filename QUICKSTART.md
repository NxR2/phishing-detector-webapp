🚀 Quick Start Guide - Phishing URL Detector
Get your Phishing Detector running in 5 minutes!

Step 1: Install Dependencies
bash
pip install -r requirements.txt
What this installs:

flask (web framework)

scikit-learn (machine learning)

pandas, numpy (data processing)

python-whois (domain age check)

requests (API calls)

Step 2: Download Dataset
Download from UCI Repository:

URL: https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.csv

Save as: Training Dataset.csv in the project root folder

File size: ~600 KB (11,055 rows)

Step 3: Train the Model
bash
cd model
python train_model.py
Expected output:

text
Classification Report:
              precision    recall  f1-score   support
           0       0.97      0.97      0.97      1106
           1       0.97      0.97      0.97      1106

    accuracy                           0.97      2212
   macro avg       0.97      0.97      0.97      2212
weighted avg       0.97      0.97      0.97      2212

ROC-AUC Score: 0.9856

Model and config saved!
Files created: phishing_model.pkl, feature_config.json
✅ Success! Model trained with ~97% accuracy.

Step 4: (Optional) Configure VirusTotal API
Get free API key:

Visit: https://www.virustotal.com/gui/join-us

Sign up for free account

Get your API key from profile

Set API key:

Windows (PowerShell):

powershell
$env:VIRUSTOTAL_API_KEY="your_api_key_here"
Mac/Linux:

bash
export VIRUSTOTAL_API_KEY="your_api_key_here"
Or edit app.py:

python
VIRUSTOTAL_API_KEY = 'your_actual_api_key_here'
⚠️ Note: App works without VirusTotal (just shows "Not available")

Step 5: Run the Application
bash
cd ..
python app.py
Expected output:

text
 * Running on http://127.0.0.1:5000
 * Debug mode: on
Press CTRL+C to quit
Step 6: Test It!
Open browser: http://127.0.0.1:5000

Test URLs to Try:
✅ Legitimate (should show low risk - Green):

https://google.com

https://github.com

https://example.com

⚠️ Suspicious (should show medium risk - Yellow):

http://login-secure-account.example.com

http://paypal-verify-login.com

❌ Phishing indicators (should show high risk - Red):

URLs with many subdomains: https://login.secure.account.verify.example.com

Newly registered domains (test with fresh domain)

URLs without SSL

🐛 Troubleshooting
Error: "Model not loaded" or "phishing_model.pkl not found"
Solution:

bash
cd model
python train_model.py
Error: "No module named 'flask'"
Solution:

bash
pip install -r requirements.txt
Error: "Training Dataset.csv not found"
Solution: Download the dataset from the UCI link in Step 2.

VirusTotal not working
Check:

API key is set correctly

Free API key limits: 4 requests/minute, 500/day

App still works without it (shows "Not available")

Port 5000 already in use
Solution: Change port in app.py:

python
app.run(debug=True, port=5001)  # Change to 5001
✅ Success Checklist
Dependencies installed

Dataset downloaded (Training Dataset.csv)

Model trained (model/phishing_model.pkl exists)

App running (http://127.0.0.1:5000)

Test URLs working

🎯 Next Steps
Test more URLs - Try various legitimate and suspicious sites

Customize UI - Edit static/style.css for colors

Deploy online - Follow README.md for Render/Railway deployment

Add to GitHub - Great portfolio project!

📚 Need More Help?
Full documentation: See README.md

Architecture details: See README.md "Architecture" section

Deployment guides: See README.md "Deployment" section

Happy detecting! 🛡️

Built for cybersecurity awareness and education