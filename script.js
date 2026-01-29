const landingScreen = document.getElementById('landing-screen');
const appInterface = document.getElementById('app-interface');
const enterBtn = document.getElementById('enterBtn');
const backBtn = document.getElementById('backBtn');
const loadingOverlay = document.getElementById('loading-overlay');

enterBtn.addEventListener('click', () => {
    landingScreen.style.opacity = '0';
    setTimeout(() => {
        landingScreen.style.display = 'none';
        appInterface.style.display = 'block';
        void appInterface.offsetWidth;
        appInterface.style.opacity = '1';
    }, 600);
});

backBtn.addEventListener('click', () => {
    appInterface.style.opacity = '0';
    setTimeout(() => {
        appInterface.style.display = 'none';
        landingScreen.style.display = 'flex';
        void landingScreen.offsetWidth;
        landingScreen.style.opacity = '1';
    }, 600);
});

const fileEml = document.getElementById('file-eml');
const filePcap = document.getElementById('file-pcap');
const raw = document.getElementById('raw');
const runBtn = document.getElementById('runBtn');
const clearBtn = document.getElementById('clearBtn');
const reportEl = document.getElementById('report');
const badge = document.getElementById('badge');
const gaugeNeedle = document.getElementById('gaugeNeedle');
const gaugeScoreText = document.getElementById('gaugeScoreText');
const fromEl = document.getElementById('fromEl');
const rpEl = document.getElementById('rpEl');
const ipsEl = document.getElementById('ipsEl');
const spfVal = document.getElementById('spfVal');
const dkimVal = document.getElementById('dkimVal');
const dmarcVal = document.getElementById('dmarcVal');
const nlpVal = document.getElementById('nlpVal');
const recommend = document.getElementById('recommend');
const exportBtn = document.getElementById('exportBtn');
const fileStatus = document.getElementById('fileStatus');
let lastPayload = null;

document.querySelectorAll('.filebox').forEach((lbl, idx) => {
    const inp = lbl.querySelector('input');
    if (!inp) {
        const hidden = document.createElement('input');
        hidden.type = 'file';
        hidden.style.display = 'none';
        if (idx === 0) hidden.accept = '.eml';
        else hidden.accept = '.pcap,.pcapng';
        lbl.appendChild(hidden);
        hidden.addEventListener('change', onFileChange);
        return;
    }
    inp.addEventListener('change', onFileChange);
});

function onFileChange(evt) {
    const f = evt.target.files[0];
    if (!f) return;
    fileStatus.textContent = `Loaded ${f.name} — ${(f.size/1024).toFixed(1)} KB`;
    if (f.name.toLowerCase().endsWith('.eml')) {
        // Limit raw text display to 500KB to prevent browser freeze on load
        if (f.size > 500000) {
            raw.value = "File too large to display raw content preview. Click Analyze to process.";
        } else {
            f.arrayBuffer().then(buf => {
                raw.value = new TextDecoder('utf-8', { fatal: false }).decode(buf);
            });
        }
    }
}

document.getElementById('file-pcap') ? .addEventListener('change', (e) => { fileStatus.textContent = 'PCAP attached'; });

clearBtn.addEventListener('click', () => {
    raw.value = '';
    reportEl.textContent = 'No analysis performed yet.';
    fileStatus.textContent = '';
    resetGauge();
});

function resetGauge() {
    gaugeNeedle.style.transform = 'rotate(-90deg)';
    gaugeScoreText.textContent = '--';
    badge.textContent = 'NO DATA';
    badge.className = 'badge maybe';
}

runBtn.addEventListener('click', async() => {
    runBtn.disabled = true;
    loadingOverlay.style.display = 'flex'; // SHOW LOADING
    reportEl.textContent = 'Analyzing…';

    try {
        const fd = new FormData();
        fd.append('raw', new Blob([raw.value || ''], { type: 'text/plain' }), 'raw.txt');
        const pcapInput = document.getElementById('file-pcap');
        if (pcapInput && pcapInput.files && pcapInput.files[0]) fd.append('pcap', pcapInput.files[0]);

        const resp = await fetch('/analyze', { method: 'POST', body: fd });
        const j = await resp.json();

        loadingOverlay.style.display = 'none'; // HIDE LOADING

        if (!j.ok) { reportEl.textContent = 'Error: ' + (j.error || 'unknown');
            runBtn.disabled = false; return; }
        lastPayload = j;
        const a = j.assessment || { verdict: 'NO DATA', score: 0, reasons: [] };
        updateGaugeAndBadge(a.score, a.verdict);
        fromEl.textContent = 'From: ' + (j.report.from || 'N/A');
        rpEl.textContent = 'Return-Path: ' + (j.report.return_path || 'N/A');
        ipsEl.textContent = 'IPs: ' + ((j.report.received_ips && j.report.received_ips.join(', ')) || 'N/A');
        spfVal.textContent = j.report.spf && j.report.spf.result ? j.report.spf.result : (j.report.spf && j.report.spf.error) || 'N/A';
        dkimVal.textContent = j.report.dkim && j.report.dkim.verified ? 'OK' : (j.report.dkim && j.report.dkim.error) || 'FAIL';
        dmarcVal.textContent = j.report.dmarc && j.report.dmarc.policy ? (j.report.dmarc.policy.p || 'none') : (j.report.dmarc && j.report.dmarc.error) || 'N/A';
        nlpVal.textContent = j.nlp && j.nlp.ok ? (j.nlp.label + ' ' + (j.nlp.score || '')) : (j.nlp && j.nlp.error) || 'not run';
        recommend.textContent = a.verdict === 'SAFE' ? 'Looks safe — still exercise caution with unexpected content.' : (a.verdict === 'MAYBE' ? 'Verify sender by independent channel before interacting.' : 'High risk — do NOT click links or open attachments.');
        reportEl.textContent = prettyReportText(j);
    } catch (e) {
        loadingOverlay.style.display = 'none';
        reportEl.textContent = 'Analysis error: ' + (e.message || e);
    }
    runBtn.disabled = false;
});

function updateGaugeAndBadge(score, verdict) {
    let pct = 0;
    if (score <= 0) pct = 10;
    else if (score <= 2) pct = 45;
    else pct = Math.min(100, 70 + (score - 3) * 10);
    const deg = (pct / 100 * 180) - 90;
    gaugeNeedle.style.transform = `rotate(${deg}deg)`;
    gaugeScoreText.textContent = pct.toFixed(0);
    badge.textContent = verdict;
    badge.className = 'badge ' + (verdict === 'SAFE' ? 'safe' : verdict === 'MAYBE' ? 'maybe' : 'risk');
}

function prettyReportText(j) {
    try {
        const r = j.report;
        const a = j.assessment;
        let lines = [];
        lines.push(`Verdict: ${a.verdict} | Score: ${a.score}`);
        lines.push('');
        lines.push('From: ' + (r.from || 'N/A'));
        lines.push('Return-Path: ' + (r.return_path || 'N/A'));
        lines.push('Received IPs: ' + ((r.received_ips && r.received_ips.join(', ')) || 'N/A'));
        lines.push('');
        lines.push('SPF: ' + (r.spf && (r.spf.result || r.spf.error) || 'N/A'));
        lines.push('DKIM: ' + (r.dkim && (r.dkim.verified ? 'OK' : r.dkim.error) || 'N/A'));
        lines.push('DMARC: ' + (r.dmarc && (r.dmarc.record || r.dmarc.error) || 'N/A'));
        lines.push('');
        lines.push('Heuristics:');
        if (r.display_spoof && r.display_spoof.ok) {
            lines.push(' - Display suspicious: ' + (r.display_spoof.suspicious ? (r.display_spoof.reasons || []).join('; ') : 'no'));
        } else lines.push(' - Display check: ' + (r.display_spoof && r.display_spoof.error || 'N/A'));
        lines.push(' - Attachments: ' + ((r.attachments && r.attachments.findings && r.attachments.findings.length) ? JSON.stringify(r.attachments.findings) : 'None flagged'));
        lines.push('');
        lines.push('NLP: ' + (j.nlp && (j.nlp.label ? j.nlp.label + ' ' + (j.nlp.score || '') : j.nlp.error) || 'not run'));
        lines.push('');
        lines.push('Reasons:');
        (a.reasons || []).forEach(x => lines.push(' - ' + x));
        lines.push('');
        lines.push('Subject: ' + (r.subject || ''));
        lines.push('');

        // --- STABILITY FIX: TRUNCATE PREVIEW ---
        let fullBody = r.full_body || '';
        if (fullBody.length > 3000) {
            fullBody = fullBody.substring(0, 3000) + '\n\n... [TEXT TRUNCATED FOR UI PERFORMANCE. SEE EXPORT FOR FULL CONTENT] ...';
        }

        lines.push('Message snippet:\n' + fullBody);
        return lines.join('\n');
    } catch (e) {
        return JSON.stringify(j, null, 2);
    }
}

exportBtn.addEventListener('click', async() => {
    if (!lastPayload) {
        alert('No report to export');
        return;
    }
    try {
        const resp = await fetch('/export', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(lastPayload)
        });

        if (!resp.ok) {
            const errorData = await resp.json();
            alert('Export failed: ' + (errorData.error || 'Unknown server error'));
            return;
        }

        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'forensic_report.pdf';
        document.body.appendChild(a);
        a.click();

        setTimeout(() => {
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }, 100);

    } catch (e) {
        console.error("Export error:", e);
        alert('Export failed: An unexpected error occurred.');
    }
});