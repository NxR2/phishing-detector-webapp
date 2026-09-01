import pandas as pd
import numpy as np
import re
import json
from urllib.parse import urlparse

# Load combined dataset
p = pd.read_csv('../phishing_urls .csv', header=0, names=['label','url'], engine='python', on_bad_lines='skip')
L = pd.read_csv('../legitimate_urls.csv', header=0, names=['label','url'], engine='python', on_bad_lines='skip')
df = pd.concat([p,L], ignore_index=True)
df = df.dropna(subset=['url','label'])
df['label'] = df['label'].str.strip().str.lower().map({'phishing':1,'legitimate':0})
df = df[df['label'].isin([0,1])]

# Feature extraction (extended)
word_re = re.compile(r'\w+')
pattern_ip = re.compile(r'^\d+\.\d+\.\d+\.\d+(:\d+)?$')

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
    # baseline
    num_dots = lu.count('.')
    num_hyphens = lu.count('-')
    has_https = 1 if lu.startswith('https') else 0
    has_at = 1 if '@' in lu else 0
    netloc2 = lu
    if '//' in lu:
        try:
            netloc2 = lu.split('//',1)[1].split('/')[0]
        except:
            netloc2 = lu
    has_ip = 1 if pattern_ip.match(netloc2) else 0
    contains_login = 1 if any(k in lu for k in ['login','signin','verify','update','secure','webscr','account']) else 0
    tokens = len(word_re.findall(s))
    digits = sum(c.isdigit() for c in s)
    has_query = 1 if '?' in s else 0
    return [len(s), num_dots, num_hyphens, has_https, has_at, has_ip, contains_login, tokens, digits, has_query, path_len, len(tld), dom_len, slash_cnt, special_cnt, ent]

print('Building features...')
X = np.array([extract_extended(u) for u in df['url']], dtype=float)
y = df['label'].astype(int).values

# Compute class statistics
classes = np.unique(y)
class_priors = {}
theta = {}
sigma = {}
for c in classes:
    Xc = X[y==c]
    class_priors[int(c)] = float(Xc.shape[0]) / X.shape[0]
    theta[int(c)] = Xc.mean(axis=0)
    sigma[int(c)] = Xc.var(axis=0) + 1e-9

# Save params as npz
np.savez('phishing_model_params.npz', classes=np.array(classes), class_priors=np.array([class_priors[int(c)] for c in classes]), theta=np.stack([theta[int(c)] for c in classes]), sigma=np.stack([sigma[int(c)] for c in classes]), feature_names=np.array(['url_length','num_dots','num_hyphens','has_https','has_at','has_ip','contains_login','num_tokens','num_digits','has_query','path_len','tld_len','dom_len','slash_cnt','special_cnt','entropy'], dtype=object))

# Also save a JSON summary
with open('phishing_model_params_summary.json','w') as f:
    json.dump({'classes': classes.tolist(), 'class_priors': {int(c): float(class_priors[int(c)]) for c in classes}, 'feature_names': ['url_length','num_dots','num_hyphens','has_https','has_at','has_ip','contains_login','num_tokens','num_digits','has_query','path_len','tld_len','dom_len','slash_cnt','special_cnt','entropy']}, f, indent=2)

print('Saved phishing_model_params.npz and summary JSON')
