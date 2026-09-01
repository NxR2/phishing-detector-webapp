import pandas as pd
import numpy as np
import joblib
import json
import os
import re

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

phish_path = 'phishing_urls .csv'
legit_path = 'legitimate_urls.csv'

print('Loading datasets...')
# Read with engine python to handle messy CSVs
p = pd.read_csv(phish_path, header=0, names=['label','url'], engine='python', encoding='utf-8', on_bad_lines='skip')
L = pd.read_csv(legit_path, header=0, names=['label','url'], engine='python', encoding='utf-8', on_bad_lines='skip')

df = pd.concat([p, L], ignore_index=True)
print('Total rows:', len(df))
# Clean
df = df.dropna(subset=['url','label'])
# Normalize label
df['label'] = df['label'].str.strip().str.lower().map({'phishing':1, 'legitimate':0})
# Drop rows with unknown labels
df = df[df['label'].isin([0,1])]
print('After filtering rows:', len(df))

feature_names = ['url_length','num_dots','num_hyphens','has_https','has_at','has_ip','contains_login','num_tokens','num_digits','has_query']

pattern_ip = re.compile(r'^\d+\.\d+\.\d+\.\d+(:\d+)?$')
word_re = re.compile(r'\w+')

def extract(url):
    u = str(url).strip()
    lu = u.lower()
    num_dots = lu.count('.')
    num_hyphens = lu.count('-')
    has_https = 1 if lu.startswith('https') else 0
    has_at = 1 if '@' in lu else 0
    netloc = lu
    if '//' in lu:
        try:
            netloc = lu.split('//',1)[1].split('/')[0]
        except:
            netloc = lu
    has_ip = 1 if pattern_ip.match(netloc) else 0
    contains_login = 1 if any(k in lu for k in ['login','signin','verify','update','secure','webscr','account']) else 0
    tokens = len(word_re.findall(u))
    digits = sum(c.isdigit() for c in u)
    has_query = 1 if '?' in u else 0
    return [len(u), num_dots, num_hyphens, has_https, has_at, has_ip, contains_login, tokens, digits, has_query]

# Build feature matrix
X_list = [extract(u) for u in df['url']]
X = np.array(X_list, dtype=float)
y = df['label'].astype(int).values

print('Feature matrix shape:', X.shape)

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Implement Gaussian Naive Bayes manually to avoid scipy/scikit dependency issues
class SimpleGaussianNB:
    def fit(self, X, y):
        self.classes_ = np.unique(y)
        self.class_count_ = {}
        self.class_prior_ = {}
        self.theta_ = {}
        self.sigma_ = {}
        for c in self.classes_:
            Xc = X[y==c]
            self.class_count_[c] = Xc.shape[0]
            self.class_prior_[c] = float(Xc.shape[0]) / X.shape[0]
            # Add small epsilon to variance
            self.theta_[c] = Xc.mean(axis=0)
            self.sigma_[c] = Xc.var(axis=0) + 1e-9
        return self
    def _log_likelihood(self, X):
        # returns log prob per class shape (n_samples, n_classes)
        n_samples = X.shape[0]
        n_classes = len(self.classes_)
        log_probs = np.zeros((n_samples, n_classes))
        for i,c in enumerate(self.classes_):
            mean = self.theta_[c]
            var = self.sigma_[c]
            # Gaussian log-likelihood
            ll = -0.5 * np.sum(np.log(2 * np.pi * var)) -0.5 * np.sum(((X - mean) **2) / var, axis=1)
            log_probs[:, i] = np.log(self.class_prior_[c]) + ll
        return log_probs
    def predict_proba(self, X):
        logp = self._log_likelihood(X)
        # stable softmax
        a = np.exp(logp - logp.max(axis=1, keepdims=True))
        probs = a / a.sum(axis=1, keepdims=True)
        return probs
    def predict(self, X):
        probs = self.predict_proba(X)
        return self.classes_[np.argmax(probs, axis=1)]

print('Training SimpleGaussianNB...')
clf = SimpleGaussianNB()
clf.fit(X_train, y_train)

# Evaluate
y_pred = clf.predict(X_test)
print('Accuracy:', accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# Save model and feature config
joblib.dump(clf, 'phishing_model.pkl')
with open('feature_config.json','w') as f:
    json.dump({'feature_names': feature_names, 'model_type': 'SimpleGaussianNB'}, f, indent=2)

print('Saved phishing_model.pkl and feature_config.json')
