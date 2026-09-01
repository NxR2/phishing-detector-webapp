import pandas as pd
import numpy as np
import joblib
import json
import re
import os
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

phish_path = 'phishing_urls .csv'
legit_path = 'legitimate_urls.csv'

print('Loading datasets for evaluation...')
P = pd.read_csv(phish_path, header=0, names=['label','url'], engine='python', on_bad_lines='skip')
L = pd.read_csv(legit_path, header=0, names=['label','url'], engine='python', on_bad_lines='skip')
df = pd.concat([P,L], ignore_index=True)
df = df.dropna(subset=['url','label'])
df['label'] = df['label'].str.strip().str.lower().map({'phishing':1,'legitimate':0})
df = df[df['label'].isin([0,1])]
print('Total eval rows:', len(df))

# Baseline feature extractor (matches current app)
word_re = re.compile(r'\w+')
pattern_ip = re.compile(r'^\d+\.\d+\.\d+\.\d+(:\d+)?$')
def extract_baseline(u):
    s = str(u).strip()
    lu = s.lower()
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
    tokens = len(word_re.findall(s))
    digits = sum(c.isdigit() for c in s)
    has_query = 1 if '?' in s else 0
    return [len(s), num_dots, num_hyphens, has_https, has_at, has_ip, contains_login, tokens, digits, has_query]

# Extended feature extractor
from urllib.parse import urlparse

def entropy(s):
    from collections import Counter
    if not s:
        return 0.0
    c = Counter(s)
    probs = [v/len(s) for v in c.values()]
    import math
    return -sum(p*math.log2(p) for p in probs)

def extract_extended(u):
    s = str(u).strip()
    lu = s.lower()
    parsed = urlparse(s if s.startswith('http') else 'http://' + s)
    netloc = parsed.netloc
    path = parsed.path or ''
    query = parsed.query or ''
    tld = netloc.split('.')[-1] if netloc else ''
    dom_len = len(netloc)
    path_len = len(path)
    slash_cnt = s.count('/')
    special_cnt = sum(1 for c in s if not c.isalnum())
    ent = entropy(s)
    base = extract_baseline(u)
    return base + [path_len, len(tld), dom_len, slash_cnt, special_cnt, ent]

# Prepare feature matrices
print('Building baseline features...')
X_bas = np.array([extract_baseline(u) for u in df['url']], dtype=float)
print('Building extended features...')
X_ext = np.array([extract_extended(u) for u in df['url']], dtype=float)

y = df['label'].astype(int).values

# Load baseline model
if os.path.exists('phishing_model.pkl'):
    try:
        baseline_model = joblib.load('phishing_model.pkl')
        print('Loaded baseline model')
    except Exception as e:
        print('Failed loading baseline model:', e)
        baseline_model = None
else:
    baseline_model = None

# Evaluate baseline
if baseline_model is not None:
    try:
        probs = baseline_model.predict_proba(X_bas)[:,1]
        preds = (probs >= 0.5).astype(int)
    except Exception:
        preds = baseline_model.predict(X_bas)
    print('\nBaseline model evaluation:')
    print('Accuracy:', accuracy_score(y, preds))
    print(classification_report(y, preds))
    print('Confusion matrix:\n', confusion_matrix(y, preds))
else:
    print('Baseline model not available for evaluation')

# Train extended model (SimpleGaussianNB like) and evaluate
print('\nTraining extended SimpleGaussianNB model...')
from sklearn.model_selection import train_test_split
Xtr, Xte, ytr, yte = train_test_split(X_ext, y, test_size=0.2, random_state=42, stratify=y)

class SimpleGaussianNB:
    def fit(self, X, y):
        self.classes_ = np.unique(y)
        self.theta_ = {}
        self.sigma_ = {}
        self.class_prior_ = {}
        for c in self.classes_:
            Xc = X[y==c]
            self.class_prior_[c] = float(Xc.shape[0]) / X.shape[0]
            self.theta_[c] = Xc.mean(axis=0)
            self.sigma_[c] = Xc.var(axis=0) + 1e-9
        return self
    def _log_likelihood(self, X):
        log_probs = np.zeros((X.shape[0], len(self.classes_)))
        for i,c in enumerate(self.classes_):
            mean = self.theta_[c]
            var = self.sigma_[c]
            ll = -0.5 * np.sum(np.log(2 * np.pi * var)) -0.5 * np.sum(((X - mean)**2) / var, axis=1)
            log_probs[:, i] = np.log(self.class_prior_[c]) + ll
        return log_probs
    def predict_proba(self, X):
        lp = self._log_likelihood(X)
        a = np.exp(lp - lp.max(axis=1, keepdims=True))
        return a / a.sum(axis=1, keepdims=True)
    def predict(self, X):
        return self.classes_[np.argmax(self.predict_proba(X), axis=1)]

clf = SimpleGaussianNB()
clf.fit(Xtr, ytr)
probs_ext = clf.predict_proba(Xte)[:,1]
preds_ext = (probs_ext >= 0.5).astype(int)
print('Extended model evaluation on test split:')
print('Accuracy:', accuracy_score(yte, preds_ext))
print(classification_report(yte, preds_ext))
print('Confusion matrix:\n', confusion_matrix(yte, preds_ext))

# Save extended model and feature config
joblib.dump(clf, 'phishing_model_extended.pkl')
with open('feature_config_extended.json','w') as f:
    json.dump({'feature_names': ['url_length','num_dots','num_hyphens','has_https','has_at','has_ip','contains_login','num_tokens','num_digits','has_query','path_len','tld_len','dom_len','slash_cnt','special_cnt','entropy'], 'model_type':'SimpleGaussianNB'}, f, indent=2)
print('Saved phishing_model_extended.pkl and feature_config_extended.json')

# Compare extended model across entire dataset
print('\nEvaluating extended model on full dataset...')
probs_full = clf.predict_proba(X_ext)[:,1]
preds_full = (probs_full >= 0.5).astype(int)
print('Accuracy full:', accuracy_score(y, preds_full))
print(classification_report(y, preds_full))
print('Confusion matrix full:\n', confusion_matrix(y, preds_full))

# Print some example false negatives and false positives
fn_idx = [i for i,(t,p) in enumerate(zip(y, preds_full)) if t==1 and p==0][:5]
fp_idx = [i for i,(t,p) in enumerate(zip(y, preds_full)) if t==0 and p==1][:5]
print('\nExample false negatives:')
for i in fn_idx:
    print(df.iloc[i]['url'])
print('\nExample false positives:')
for i in fp_idx:
    print(df.iloc[i]['url'])

print('\nDone')
