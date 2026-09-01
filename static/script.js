async function checkURL() {
    const url = document.getElementById('urlInput').value.trim();
    const resultDiv = document.getElementById('result');
    const loadingDiv = document.getElementById('loading');
    
    if (!url) {
        alert('Please enter a URL');
        return;
    }
    
    loadingDiv.style.display = 'block';
    resultDiv.style.display = 'none';
    
    try {
        const response = await fetch('/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });
        
        const data = await response.json();
        
        if (data.error) {
            alert(data.error);
            return;
        }
        
        document.getElementById('resultLabel').textContent = data.label;
        
        if (data.label === 'Phishing') {
            document.getElementById('resultLabel').style.color = '#f44336';
        } else if (data.label === 'Suspicious') {
            document.getElementById('resultLabel').style.color = '#ff9800';
        } else {
            document.getElementById('resultLabel').style.color = '#00c853';
        }
        
        document.getElementById('riskScore').textContent = data.risk_score;
        document.getElementById('mlRiskScore').textContent = data.ml_risk_score;
        document.getElementById('riskFill').style.width = data.risk_score + '%';
        
        const riskFactorsSection = document.getElementById('riskFactorsSection');
        const riskFactorList = document.getElementById('riskFactorList');
        riskFactorList.innerHTML = '';
        
        if (data.risk_factors && data.risk_factors.length > 0) {
            riskFactorsSection.style.display = 'block';
            data.risk_factors.forEach(factor => {
                const li = document.createElement('li');
                li.textContent = '⚠️ ' + factor;
                riskFactorList.appendChild(li);
            });
        } else {
            riskFactorsSection.style.display = 'none';
        }
        
        const featureList = document.getElementById('featureList');
        featureList.innerHTML = '';
        data.top_features.forEach(feature => {
            const li = document.createElement('li');
            li.textContent = '• ' + feature;
            featureList.appendChild(li);
        });
        
        document.getElementById('domainCreation').textContent = data.domain_info.creation_date;
        document.getElementById('domainAge').textContent = data.domain_info.age_days || 'Unknown';
        
        const domainWarning = document.getElementById('domainWarning');
        if (data.domain_info.is_new) {
            domainWarning.textContent = '⚠️ Warning: Domain is less than 30 days old!';
            domainWarning.style.display = 'block';
        } else {
            domainWarning.style.display = 'none';
        }
        
        document.getElementById('sslValid').textContent = data.ssl_info.valid ? '✅ Yes' : '❌ No';
        document.getElementById('sslValid').style.color = data.ssl_info.valid ? '#00c853' : '#f44336';
        document.getElementById('sslIssuer').textContent = data.ssl_info.issuer;
        document.getElementById('sslExpires').textContent = data.ssl_info.expires;
        
        const sslWarning = document.getElementById('sslWarning');
        if (!data.ssl_info.valid) {
            sslWarning.textContent = '⚠️ Warning: No valid SSL certificate!';
            sslWarning.style.display = 'block';
        } else if (data.ssl_info.is_expiring_soon) {
            sslWarning.textContent = `⚠️ Warning: SSL certificate expiring in ${data.ssl_info.days_until_expiry} days!`;
            sslWarning.style.display = 'block';
        } else {
            sslWarning.style.display = 'none';
        }
        
        const vtStatus = document.getElementById('vtStatus');
        const vtStats = document.getElementById('vtStats');
        const vtWarning = document.getElementById('vtWarning');
        
        if (data.virustotal_info.available) {
            vtStatus.textContent = 'Checked';
            vtStats.textContent = `Malicious: ${data.virustotal_info.malicious} | Suspicious: ${data.virustotal_info.suspicious} | Harmless: ${data.virustotal_info.harmless}`;
            vtStats.className = 'vt-stats';
            
            if (data.virustotal_info.is_malicious) {
                vtWarning.textContent = '⚠️ Warning: URL flagged by security vendors!';
                vtWarning.style.display = 'block';
                vtStats.style.color = '#f44336';
            } else {
                vtWarning.style.display = 'none';
                vtStats.style.color = '#00c853';
            }
        } else {
            vtStatus.textContent = 'Not available in VirusTotal database';
            vtStats.textContent = '';
            vtWarning.style.display = 'none';
        }
        
        resultDiv.style.display = 'block';
    } catch (error) {
        alert('Error: ' + error.message);
    } finally {
        loadingDiv.style.display = 'none';
    }
}