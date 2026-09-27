// RedFlag — Dedicated Malicious Link & URL Detection Logic

// Smooth scroll helper
function scrollToSection(id) {
  const el = document.getElementById(id);
  if (el) {
    el.scrollIntoView({ behavior: 'smooth' });
    const input = document.getElementById('scan-url');
    if (input) input.focus();
  }
}

// Load real-world phishing URL samples
function loadSample(type) {
  const urlInput = document.getElementById('scan-url');
  if (!urlInput) return;

  const samples = {
    sbi_kyc: "http://sbi-kyc-update-portal.xyz/login",
    hdfc_reward: "http://hdfc-rewards-claim.top/verify",
    ip_host: "http://192.168.1.100/paytm/verify",
    at_symbol: "http://google.com@evil-phishing-host.live/login",
    non_standard_port: "http://banking-portal-secure.site:8080/auth",
    legit_sbi: "https://www.onlinesbi.sbi/portal"
  };

  urlInput.value = samples[type] || "";
  runScan();
}

// Run URL Scanner
async function runScan() {
  const urlInput = document.getElementById('scan-url');
  const rawUrl = urlInput ? urlInput.value.trim() : "";

  if (!rawUrl) {
    alert("Please enter a URL to inspect.");
    if (urlInput) urlInput.focus();
    return;
  }

  const btn = document.getElementById('btn-scan');
  if (btn) {
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1.5"></i> Inspecting URL Heuristics...';
    btn.disabled = true;
  }

  try {
    const res = await fetch('/api/v1/scan/url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: rawUrl })
    });

    if (!res.ok) {
      throw new Error(`Server returned HTTP ${res.status}`);
    }

    const data = await res.json();
    renderScanResult(data);
  } catch (err) {
    alert("Error inspecting URL: " + err.message);
  } finally {
    if (btn) {
      btn.innerHTML = '<i class="fa-solid fa-shield-halved mr-1.5"></i> Analyse URL Now';
      btn.disabled = false;
    }
  }
}

function renderScanResult(data) {
  const placeholder = document.getElementById('scan-placeholder');
  const resCard = document.getElementById('scan-result');
  if (placeholder) placeholder.classList.add('hidden');
  if (resCard) resCard.classList.remove('hidden');

  const score = data.risk_score;
  const features = data.url_features;

  // Score & text
  document.getElementById('risk-score-num').textContent = score;
  document.getElementById('risk-category').textContent = data.category.replace(/_/g, ' ');
  document.getElementById('risk-explanation').textContent = data.explanation;
  document.getElementById('inspected-url-display').textContent = data.url;

  const badge = document.getElementById('risk-badge');
  const bar = document.getElementById('risk-bar');
  bar.style.width = `${score}%`;

  if (score >= 85) {
    badge.textContent = "CRITICAL REDFLAG";
    badge.className = "px-3.5 py-1 rounded-full text-xs font-extrabold uppercase tracking-wider bg-red-100 text-redflag border border-red-300";
    bar.className = "h-3 rounded-full bg-redflag";
  } else if (score >= 60) {
    badge.textContent = "HIGH RISK";
    badge.className = "px-3.5 py-1 rounded-full text-xs font-extrabold uppercase tracking-wider bg-orange-100 text-orange-700 border border-orange-300";
    bar.className = "h-3 rounded-full bg-orange-500";
  } else if (score >= 30) {
    badge.textContent = "SUSPICIOUS";
    badge.className = "px-3.5 py-1 rounded-full text-xs font-extrabold uppercase tracking-wider bg-amber-100 text-amber-800 border border-amber-300";
    bar.className = "h-3 rounded-full bg-amber-500";
  } else {
    badge.textContent = "SAFE / BENIGN";
    badge.className = "px-3.5 py-1 rounded-full text-xs font-extrabold uppercase tracking-wider bg-emerald-100 text-emerald-800 border border-emerald-300";
    bar.className = "h-3 rounded-full bg-emerald-500";
  }

  // Feature Metric Cards
  document.getElementById('metric-domain').textContent = features.domain || "N/A";
  document.getElementById('metric-entropy').textContent = features.entropy ? `${features.entropy}` : "0.0";
  document.getElementById('metric-tld').textContent = features.detected_tld ? `.${features.detected_tld}` : "None";
  
  const brandEl = document.getElementById('metric-brand');
  if (features.is_official_domain) {
    brandEl.innerHTML = `<span class="text-emerald-700 font-bold"><i class="fa-solid fa-circle-check text-emerald-600 mr-1"></i>Official ${features.official_brand_name || 'Domain'}</span>`;
  } else if (features.brand_impersonated) {
    brandEl.innerHTML = `<span class="text-redflag font-bold"><i class="fa-solid fa-triangle-exclamation mr-1"></i>Mimics ${features.brand_impersonated}</span>`;
  } else {
    brandEl.innerHTML = `<span class="text-emerald-700 font-semibold"><i class="fa-solid fa-check mr-1"></i>None Detected</span>`;
  }

  document.getElementById('metric-subdomains').textContent = `${features.subdomain_count} (Len: ${features.url_length})`;
  document.getElementById('metric-protocol').textContent = `${features.protocol.toUpperCase()}${features.port ? ` : ${features.port}` : ''}`;

  // Contributing Factors List
  const factorsList = document.getElementById('factors-list');
  factorsList.innerHTML = '';
  (data.contributing_factors || []).forEach(f => {
    const isOfficial = f.includes("Verified Official");
    const iconClass = isOfficial ? "fa-circle-check text-emerald-600" : "fa-triangle-exclamation text-redflag";
    const bgClass = isOfficial ? "bg-emerald-50 border-emerald-200 text-emerald-900" : "bg-canvas border-accent text-slate-800";
    factorsList.innerHTML += `
      <li class="flex items-start gap-2 ${bgClass} p-2.5 rounded-lg border">
        <i class="fa-solid ${iconClass} mt-0.5 text-xs flex-shrink-0"></i>
        <span class="text-xs font-medium">${f}</span>
      </li>
    `;
  });
  if (!factorsList.innerHTML) {
    factorsList.innerHTML = '<li class="text-slate-500 text-xs italic">No suspicious heuristic indicators detected.</li>';
  }

  // Mitigation Advice List
  const adviceList = document.getElementById('advice-list');
  adviceList.innerHTML = '';
  (data.mitigation_advice || []).forEach(a => {
    adviceList.innerHTML += `<li class="text-xs text-red-900">${a}</li>`;
  });
}
