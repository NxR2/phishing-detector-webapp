import pandas as pd
import requests
import random
import time
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Load dataset
p = pd.read_csv('../phishing_urls .csv', header=0, names=['label','url'], engine='python', on_bad_lines='skip')
L = pd.read_csv('../legitimate_urls.csv', header=0, names=['label','url'], engine='python', on_bad_lines='skip')
df = pd.concat([p, L], ignore_index=True)
df = df.dropna(subset=['url','label'])
df['label'] = df['label'].str.strip().str.lower().map({'phishing':1,'legitimate':0})
df = df[df['label'].isin([0,1])]

# sample balanced 1000 rows if possible
n = 1000
ph = df[df['label']==1]
le = df[df['label']==0]
ns = min(len(ph), len(le), n//2)
phs = ph.sample(ns, random_state=42)
les = le.sample(ns, random_state=42)
sample = pd.concat([phs, les]).sample(frac=1, random_state=42).reset_index(drop=True)

labels = []
preds = []
probs = []

for i,row in sample.iterrows():
    url = row['url']
    try:
        r = requests.post('http://127.0.0.1:5000/predict', json={'url': url}, timeout=5)
        data = r.json()
        if 'probability' in data:
            prob = float(data['probability'])
            label = 1 if data.get('label','legitimate')=='phishing' else 0
        else:
            prob = 0.0
            label = 1 if 'phishing' in str(data.get('label','')) else 0
        preds.append(label)
        probs.append(prob)
    except Exception as e:
        preds.append(0)
        probs.append(0.0)
    labels.append(int(row['label']))
    if (i+1) % 100 == 0:
        print(f"Processed {i+1}/{len(sample)}")
    time.sleep(0.01)

print('Done requests. Computing metrics...')
print('Accuracy:', accuracy_score(labels, preds))
print(classification_report(labels, preds))
print('Confusion matrix:\n', confusion_matrix(labels, preds))

# Save raw results
res = pd.DataFrame({'url': sample['url'], 'true': labels, 'pred': preds, 'prob': probs})
res.to_csv('predict_test_results.csv', index=False)
print('Saved predict_test_results.csv')
