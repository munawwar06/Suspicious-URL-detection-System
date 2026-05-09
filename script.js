let history = JSON.parse(localStorage.getItem('phish_history') || '[]');
let activeTab = 'scanner';

// Configuration Constants
const PHISHING_KW = ['login','verify','secure','update','account','bank','paypal','amazon','apple','microsoft','confirm','password','reset','suspend','urgent','free','prize','winner','claim','click','limited'];
const BAD_TLDS = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.click','.download'];
const SHORTENERS = ['bit.ly','tinyurl.com','goo.gl','t.co','ow.ly','buff.ly','rebrand.ly','short.io','tr.im','is.gd','cutt.ly'];

function showTab(tab, btn) {
    ['scanner', 'history', 'analytics', 'tips'].forEach(t => {
        document.getElementById('tab-' + t).style.display = (t === tab) ? 'block' : 'none';
    });
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeTab = tab;
    if (tab === 'history') renderHistory();
    if (tab === 'analytics') renderAnalytics();
}

function loadSample(url) {
    document.getElementById('url-input').value = url;
}

function analyzeURL(raw) {
    const url = raw.trim();
    let score = 0;
    const checks = [];
    
    // Protocol check
    const isHTTPS = url.startsWith('https://');
    const isHTTP = url.startsWith('http://');
    if (!isHTTPS && isHTTP) {
        score += 25;
        checks.push({ name: 'Insecure protocol', detail: 'Uses HTTP instead of HTTPS', status: 'fail' });
    } else if (isHTTPS) {
        checks.push({ name: 'Secure protocol', detail: 'HTTPS encryption active', status: 'pass' });
    } else {
        score += 15;
        checks.push({ name: 'Unknown protocol', detail: 'No valid protocol detected', status: 'warn' });
    }

    // Subdomain & Domain logic
    let domain = '';
    try {
        domain = new URL(url.startsWith('http') ? url : 'https://' + url).hostname;
    } catch (e) {
        domain = url;
    }
    const parts = domain.split('.');
    
    // TLD Analysis
    const tld = '.' + parts[parts.length - 1];
    if (BAD_TLDS.includes(tld)) {
        score += 20;
        checks.push({ name: 'Suspicious TLD', detail: `"${tld}" is high-risk`, status: 'fail' });
    } else {
        checks.push({ name: 'Top-level domain', detail: `"${tld}" looks normal`, status: 'pass' });
    }

    // Keyword Check
    const lower = url.toLowerCase();
    const found = PHISHING_KW.filter(k => lower.includes(k));
    if (found.length >= 3) {
        score += 20;
        checks.push({ name: 'Phishing keywords', detail: `Detected: ${found.slice(0, 3).join(', ')}`, status: 'fail' });
    } else {
        checks.push({ name: 'Keyword analysis', detail: 'Checked against threat list', status: 'pass' });
    }

    score = Math.min(100, Math.max(0, score));
    const cls = score <= 30 ? 'safe' : score <= 70 ? 'suspicious' : 'dangerous';
    const label = score <= 30 ? 'SAFE' : score <= 70 ? 'SUSPICIOUS' : 'DANGEROUS';

    return { score, cls, label, checks, url };
}

async function doScan() {
    const raw = document.getElementById('url-input').value.trim();
    if (!raw) return;

    const btn = document.getElementById('scan-btn');
    btn.disabled = true;
    const ra = document.getElementById('result-area');
    
    // Fake loading animation
    ra.innerHTML = `<div class="loading-wrap"><div class="spinner"></div><div class="loading-status">SCANNING...</div></div>`;
    
    await new Promise(r => setTimeout(r, 1500));
    
    btn.disabled = false;
    const r = analyzeURL(raw);
    
    // Save to history
    history.unshift({ ...r, time: new Date().toLocaleString() });
    if (history.length > 50) history.pop();
    localStorage.setItem('phish_history', JSON.stringify(history));
    
    renderResult(r, ra);
}

function renderResult(r, container) {
    const iconMap = { pass: '✓', fail: '✗', warn: '!' };
    container.innerHTML = `
        <div class="result-card ${r.cls}">
            <div class="result-top">
                <div>
                    <div class="result-badge ${r.cls}">${r.label}</div>
                </div>
                <div class="result-score-wrap">
                    <div class="result-score ${r.cls}">${r.score}</div>
                    <div class="score-label">RISK SCORE</div>
                </div>
            </div>
            <div class="score-bar-wrap"><div class="score-bar ${r.cls}" style="width:${r.score}%"></div></div>
            <div class="result-url">${r.url}</div>
            <div class="checks-grid">${r.checks.map(c => `
                <div class="check-item">
                    <div class="check-icon ${c.status}">${iconMap[c.status]}</div>
                    <div><div class="check-name">${c.name}</div><div class="check-detail">${c.detail}</div></div>
                </div>`).join('')}
            </div>
        </div>`;
}

function renderHistory() {
    const c = document.getElementById('history-content');
    if (!history.length) {
        c.innerHTML = '<div class="history-empty">// No scans recorded</div>';
        return;
    }
    c.innerHTML = `
        <button class="clear-btn" onclick="clearHistory()">✕ Clear History</button>
        <div class="history-list">${history.map((h, i) => `
            <div class="history-item" onclick="reloadScan(${i})">
                <div class="history-dot ${h.cls}"></div>
                <div class="history-url">${h.url}</div>
                <div class="history-score ${h.cls}">${h.score}</div>
            </div>`).join('')}
        </div>`;
}

function clearHistory() {
    history = [];
    localStorage.removeItem('phish_history');
    renderHistory();
}

function reloadScan(i) {
    const h = history[i];
    showTab('scanner', document.querySelector('.nav-btn'));
    document.getElementById('url-input').value = h.url;
    renderResult(h, document.getElementById('result-area'));
}
