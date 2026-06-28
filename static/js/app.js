const COMP_ICONS = {
    web_portal: '🌐', api_gateway: '🔀', core_banking: '🏛️',
    database: '🗄️', atm_network: '🏧', admin_console: '⚙️',
    firewall: '🛡️', auth_server: '🔐', message_queue: '📨', log_server: '📋',
};

const RISK_COLORS = {
    'Kritik': '#dc2626', 'Yüksek': '#ea580c',
    'Orta': '#d97706', 'Düşük': '#65a30d', 'Çok Düşük': '#16a34a',
};

const STRIDE_COLORS = {
    'S': '#f87171', 'T': '#fb923c', 'R': '#facc15',
    'I': '#38bdf8', 'D': '#a78bfa', 'E': '#f472b6',
};

let selectedComponents = new Set();
let lastResult = null;

function toggleComponent(el) {
    const tip = el.dataset.tip;
    if (selectedComponents.has(tip)) {
        selectedComponents.delete(tip);
        el.classList.remove('selected');
    } else {
        selectedComponents.add(tip);
        el.classList.add('selected');
    }
    document.getElementById('btnAnalyze').disabled = selectedComponents.size === 0;
}

async function runAnalysis() {
    const modelAdi = document.getElementById('modelAdi').value.trim() || 'Bankacılık Ağı Modeli';
    const components = [...selectedComponents].map((tip, i) => ({
        id: `comp_${i}`, tip,
    }));

    document.getElementById('loadingOverlay').style.display = 'flex';
    document.getElementById('analyzeError').style.display = 'none';

    try {
        const res = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ components, model_adi: modelAdi }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.hata || 'Analiz başarısız.');
        lastResult = data;
        renderResults(data);
    } catch (e) {
        const err = document.getElementById('analyzeError');
        err.textContent = e.message;
        err.style.display = 'block';
    } finally {
        document.getElementById('loadingOverlay').style.display = 'none';
    }
}

function renderResults(data) {
    const panel = document.getElementById('resultsPanel');
    panel.style.display = 'block';
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

    document.getElementById('resultModelAdi').textContent = data.model_adi;
    document.getElementById('resultDate').textContent = data.analiz_tarihi;

    const badge = document.getElementById('overallRiskBadge');
    badge.textContent = data.genel_risk;
    badge.style.background = RISK_COLORS[data.genel_risk] || '#475569';

    document.getElementById('sumComponents').textContent = data.bilesenler.length;
    document.getElementById('sumThreats').textContent = data.toplam_tehdit;
    document.getElementById('sumCritical').textContent = data.onem_dagılımı['Kritik'] || 0;
    document.getElementById('sumHigh').textContent = data.onem_dagılımı['Yüksek'] || 0;

    renderSeverityBars(data.onem_dagılımı, data.toplam_tehdit);
    renderThreatList(data.bilesenler);
}

function renderSeverityBars(counts, total) {
    const container = document.getElementById('severityBars');
    const levels = ['Kritik', 'Yüksek', 'Orta', 'Düşük', 'Çok Düşük'];
    container.innerHTML = levels.map(lv => {
        const n = counts[lv] || 0;
        const pct = total > 0 ? Math.round((n / total) * 100) : 0;
        const color = RISK_COLORS[lv];
        return `<div class="sev-row">
            <span class="sev-label">${lv}</span>
            <div class="sev-bar-wrap">
                <div class="sev-bar" style="width:${pct}%;background:${color}"></div>
            </div>
            <span class="sev-count">${n}</span>
        </div>`;
    }).join('');
}

function renderThreatList(bilesenler) {
    const container = document.getElementById('threatList');
    container.innerHTML = bilesenler.map((b, idx) => {
        const cards = b.tehditler.map(t => `
            <div class="threat-card" style="border-color:${t.risk_rengi}">
                <span class="stride-badge" style="background:${STRIDE_COLORS[t.stride_kodu] || '#475569'}">${t.stride_kodu} — ${t.stride_adi}</span>
                <div class="threat-body">
                    <div class="threat-title">${t.baslik}</div>
                    <div class="threat-desc">${t.aciklama}</div>
                    <div class="threat-oneri">${t.oneri}</div>
                </div>
                <span class="risk-chip" style="background:${t.risk_rengi}">${t.risk_seviyesi}<br><small style="font-weight:400">${t.risk_skoru}/25</small></span>
            </div>
        `).join('');

        return `<div class="comp-section">
            <div class="comp-header" onclick="toggleSection('sec_${idx}', this)">
                <span class="comp-header-icon">${COMP_ICONS[b.tip] || '📦'}</span>
                <span class="comp-header-name">${b.isim}</span>
                <span class="comp-threat-count">${b.tehdit_sayisi} tehdit</span>
                <span class="comp-toggle">▼</span>
            </div>
            <div id="sec_${idx}" class="threat-cards">${cards}</div>
        </div>`;
    }).join('');
}

function toggleSection(id, header) {
    const el = document.getElementById(id);
    const toggle = header.querySelector('.comp-toggle');
    if (el.style.display === 'none') {
        el.style.display = 'flex';
        toggle.textContent = '▼';
    } else {
        el.style.display = 'none';
        toggle.textContent = '▶';
    }
}

function exportJSON() {
    if (!lastResult) return;
    const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `stride_${lastResult.model_id}.json`;
    a.click();
}

// Geçmişten geri yükleme desteği
const params = new URLSearchParams(window.location.search);
if (params.has('components')) {
    try {
        const comps = JSON.parse(params.get('components'));
        const modelAdi = params.get('model_adi') || '';
        comps.forEach(c => {
            const el = document.querySelector(`.comp-card[data-tip="${c.tip}"]`);
            if (el) toggleComponent(el);
        });
        document.getElementById('modelAdi').value = modelAdi;
        if (comps.length > 0) runAnalysis();
    } catch (e) { /* geçersiz parametre, yoksay */ }
}
