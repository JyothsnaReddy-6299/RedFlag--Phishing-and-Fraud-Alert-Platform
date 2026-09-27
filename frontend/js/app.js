// RedFlag Dashboard Application Logic

// Smooth scroll helper
function scrollToSection(id) {
  const el = document.getElementById(id);
  if (el) {
    el.scrollIntoView({ behavior: 'smooth' });
  }
}

// Tab switching
function switchTab(tab) {
  const tabs = ['report', 'feed', 'graph', 'investigate'];
  tabs.forEach(t => {
    const sec = document.getElementById(`section-${t}`);
    if (sec) sec.classList.add('hidden');
    
    const tabBtn = document.getElementById(`tab-${t}`);
    if (tabBtn) {
      tabBtn.className = "tab-btn px-3.5 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 bg-white text-slate-700 border border-accent hover:bg-slate-50";
    }
  });

  const activeSec = document.getElementById(`section-${tab}`);
  if (activeSec) activeSec.classList.remove('hidden');

  const activeBtn = document.getElementById(`tab-${tab}`);
  if (activeBtn) {
    activeBtn.className = "tab-btn px-3.5 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 bg-redflag text-white shadow-sm";
  }

  if (tab === 'feed') loadReportsFeed();
  if (tab === 'graph') loadGraphData();
}

// Load sample presets
function loadSample(type) {
  const msgInput = document.getElementById('scan-text');
  const urlInput = document.getElementById('scan-url');

  if (type === 'tneb_tanglish') {
    msgInput.value = "Ungal TNEB power bill kattavum udane illaiyendral innum 2 hours la current vettpadum. Send money to tneb.officer984@okhdfcbank or call 9840123456";
    urlInput.value = "";
  } else if (type === 'sbi_english') {
    msgInput.value = "Dear SBI customer, your net banking is suspended! Update your KYC urgently or debit card will be blocked within 24 hours. Click http://sbi-kyc-update-portal.xyz/login";
    urlInput.value = "http://sbi-kyc-update-portal.xyz/login";
  } else if (type === 'tamil_script') {
    msgInput.value = "அன்புள்ள வாடிக்கையாளரே, உங்களின் மின்சார கட்டணம் செலுத்தப்படவில்லை. இன்றிரவு மின்சாரம் துண்டிக்கப்படும். உடனே தொடர்பு கொள்ளவும்: 9840123456";
    urlInput.value = "";
  } else if (type === 'phish_url') {
    msgInput.value = "";
    urlInput.value = "http://hdfc-rewards-claim.top/verify";
  } else if (type === 'legit_url') {
    msgInput.value = "";
    urlInput.value = "https://www.onlinesbi.sbi";
  }
}

// Run Scanner
async function runScan() {
  const text = document.getElementById('scan-text').value.trim();
  const url = document.getElementById('scan-url').value.trim();

  if (!text && !url) {
    alert("Please enter a message or URL to scan.");
    return;
  }

  const btn = document.getElementById('btn-scan');
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Analyzing Indicators...';
  btn.disabled = true;

  try {
    const res = await fetch('/api/v1/scan/unified', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, url })
    });
    const data = await res.json();
    renderScanResult(data);
  } catch (err) {
    alert("Error scanning threat: " + err.message);
  } finally {
    btn.innerHTML = '<i class="fa-solid fa-shield-halved"></i> Analyze Threat Indicators';
    btn.disabled = false;
  }
}

function renderScanResult(data) {
  document.getElementById('scan-placeholder').classList.add('hidden');
  const resCard = document.getElementById('scan-result');
  resCard.classList.remove('hidden');

  const risk = data.risk_assessment;
  const score = risk.risk_score;

  // Score & text
  document.getElementById('risk-score-num').textContent = score;
  document.getElementById('risk-category').textContent = risk.primary_category.replace(/_/g, ' ');
  document.getElementById('risk-explanation').textContent = risk.explanation;

  const badge = document.getElementById('risk-badge');
  const bar = document.getElementById('risk-bar');
  bar.style.width = `${score}%`;

  if (score >= 85) {
    badge.textContent = "CRITICAL REDFLAG";
    badge.className = "px-3 py-1 rounded-full text-xs font-extrabold uppercase tracking-wider bg-red-100 text-redflag border border-red-300";
    bar.className = "h-3 rounded-full bg-redflag";
  } else if (score >= 60) {
    badge.textContent = "HIGH RISK";
    badge.className = "px-3 py-1 rounded-full text-xs font-extrabold uppercase tracking-wider bg-orange-100 text-orange-700 border border-orange-300";
    bar.className = "h-3 rounded-full bg-orange-500";
  } else if (score >= 30) {
    badge.textContent = "SUSPICIOUS";
    badge.className = "px-3 py-1 rounded-full text-xs font-extrabold uppercase tracking-wider bg-amber-100 text-amber-800 border border-amber-300";
    bar.className = "h-3 rounded-full bg-amber-500";
  } else {
    badge.textContent = "SAFE / BENIGN";
    badge.className = "px-3 py-1 rounded-full text-xs font-extrabold uppercase tracking-wider bg-emerald-100 text-emerald-800 border border-emerald-300";
    bar.className = "h-3 rounded-full bg-emerald-500";
  }

  // Render Entities
  const entBox = document.getElementById('entities-container');
  entBox.innerHTML = '';
  const ents = data.extracted_entities;

  (ents.phone_numbers || []).forEach(p => {
    entBox.innerHTML += `<span class="bg-tint text-slate-800 border border-accent font-semibold px-2.5 py-1 rounded-lg text-xs mono"><i class="fa-solid fa-phone text-redflag text-[10px] mr-1"></i>${p}</span>`;
  });
  (ents.upi_ids || []).forEach(u => {
    entBox.innerHTML += `<span class="bg-tint text-slate-800 border border-accent font-semibold px-2.5 py-1 rounded-lg text-xs mono"><i class="fa-solid fa-money-bill-transfer text-emerald-600 text-[10px] mr-1"></i>${u}</span>`;
  });
  (ents.urls || []).forEach(u => {
    entBox.innerHTML += `<span class="bg-tint text-slate-800 border border-accent font-semibold px-2.5 py-1 rounded-lg text-xs mono"><i class="fa-solid fa-link text-purple-600 text-[10px] mr-1"></i>${u.slice(0, 32)}...</span>`;
  });
  (ents.organizations || []).forEach(o => {
    entBox.innerHTML += `<span class="bg-tint text-slate-800 border border-accent font-semibold px-2.5 py-1 rounded-lg text-xs"><i class="fa-solid fa-building text-amber-600 text-[10px] mr-1"></i>${o}</span>`;
  });

  if (!entBox.innerHTML) {
    entBox.innerHTML = '<span class="text-xs text-slate-400 italic">None extracted</span>';
  }

  // Contributing Factors
  const factorsList = document.getElementById('factors-list');
  factorsList.innerHTML = '';
  (risk.contributing_factors || []).forEach(f => {
    factorsList.innerHTML += `<li class="flex items-start gap-1.5"><i class="fa-solid fa-triangle-exclamation text-redflag mt-0.5 text-[10px]"></i> <span>${f}</span></li>`;
  });
  if (!factorsList.innerHTML) {
    factorsList.innerHTML = '<li class="text-slate-400 italic">No malicious factors detected.</li>';
  }

  // Mitigation Advice
  const adviceList = document.getElementById('advice-list');
  adviceList.innerHTML = '';
  (risk.mitigation_advice || []).forEach(a => {
    adviceList.innerHTML += `<li>${a}</li>`;
  });
}

// Submit Report
async function submitCommunityReport(e) {
  e.preventDefault();
  const payload = {
    scam_category: document.getElementById('rpt-category').value || null,
    raw_message: document.getElementById('rpt-message').value || null,
    phone_number: document.getElementById('rpt-phone').value || null,
    upi_id: document.getElementById('rpt-upi').value || null,
    raw_url: document.getElementById('rpt-url').value || null,
    organization: document.getElementById('rpt-org').value || null,
    location_city: document.getElementById('rpt-city').value || null,
    location_area: document.getElementById('rpt-area').value || null,
    description: document.getElementById('rpt-desc').value || null
  };

  try {
    const res = await fetch('/api/v1/reports', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    const successBox = document.getElementById('report-success');
    successBox.classList.remove('hidden');
    successBox.innerHTML = `<strong>✅ RedFlag Filed Successfully!</strong><br/>Tracking ID: <code class="mono font-bold">${data.report_id}</code> | Automated Risk Score: ${data.initial_risk_score}/100. Submitted for analyst review.`;
    document.getElementById('report-form').reset();
  } catch (err) {
    alert("Error filing report: " + err.message);
  }
}

// Load Reports Feed
async function loadReportsFeed() {
  const tbody = document.getElementById('feed-table-body');
  tbody.innerHTML = '<tr><td colspan="8" class="p-4 text-center text-slate-400">Loading live reports...</td></tr>';
  try {
    const res = await fetch('/api/v1/reports?limit=50');
    const reports = await res.json();
    tbody.innerHTML = '';
    if (reports.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="p-4 text-center text-slate-400">No community reports filed yet.</td></tr>';
      return;
    }

    reports.forEach(r => {
      const statusColor = r.status === 'VERIFIED' ? 'text-red-700 bg-red-100 border-red-300' : 'text-amber-800 bg-amber-100 border-amber-300';
      tbody.innerHTML += `
        <tr class="hover:bg-slate-50 transition">
          <td class="p-3 mono font-bold text-redflag">${r.report_id}</td>
          <td class="p-3 font-medium">${r.scam_category}</td>
          <td class="p-3 mono text-slate-600">${r.masked_phone || '-'}</td>
          <td class="p-3 mono text-slate-600">${r.masked_upi || '-'}</td>
          <td class="p-3 font-medium">${r.organization || '-'}</td>
          <td class="p-3 text-slate-600">${r.location_area || r.location_city || '-'}</td>
          <td class="p-3 font-extrabold mono text-slate-900">${r.initial_risk_score}</td>
          <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold border ${statusColor}">${r.status}</span></td>
        </tr>
      `;
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="p-4 text-center text-red-500">Failed to load feed: ${err.message}</td></tr>`;
  }
}

// Graph Visualizer
let networkInstance = null;

async function loadGraphData() {
  try {
    const [graphRes, campRes] = await Promise.all([
      fetch('/api/v1/graph/full'),
      fetch('/api/v1/graph/campaigns')
    ]);
    const graphData = await graphRes.json();
    const campaigns = await campRes.json();

    renderNetwork(graphData, 'network-canvas');
    renderCampaignsList(campaigns);
  } catch (err) {
    console.error("Error loading graph: ", err);
  }
}

function renderNetwork(graphData, containerId) {
  const container = document.getElementById(containerId);
  
  const nodeColors = {
    REPORT: '#3b82f6',
    PHONE: '#FF0000',
    UPI: '#10b981',
    URL: '#8b5cf6',
    DOMAIN: '#a855f7',
    BRAND: '#f59e0b',
    LOCATION: '#0d9488',
    SCAM_TYPE: '#eab308'
  };

  const nodes = new vis.DataSet(
    graphData.nodes.map(n => ({
      id: n.id,
      label: n.label,
      color: {
        background: nodeColors[n.type] || '#64748b',
        border: '#ffffff',
        highlight: { background: '#FF0000', border: '#ffffff' }
      },
      font: { color: '#ffffff', size: 12, face: 'Plus Jakarta Sans' },
      shape: n.type === 'REPORT' ? 'box' : 'dot',
      size: n.type === 'REPORT' ? 22 : 16
    }))
  );

  const edges = new vis.DataSet(
    graphData.edges.map(e => ({
      from: e.source,
      to: e.target,
      label: e.relationship,
      color: { color: '#BBD5DA', highlight: '#FF0000' },
      font: { color: '#cbd5e1', size: 9, align: 'middle' },
      arrows: 'to',
      smooth: { type: 'continuous' }
    }))
  );

  const options = {
    physics: {
      stabilization: false,
      barnesHut: {
        gravitationalConstant: -2200,
        springConstant: 0.04,
        springLength: 95
      }
    },
    interaction: {
      hover: true,
      tooltipDelay: 200,
      zoomView: true
    }
  };

  if (containerId === 'network-canvas' && networkInstance) {
    networkInstance.destroy();
  }

  const net = new vis.Network(container, { nodes, edges }, options);
  if (containerId === 'network-canvas') networkInstance = net;
  return net;
}

function renderCampaignsList(campaigns) {
  const box = document.getElementById('campaigns-container');
  box.innerHTML = '';
  if (!campaigns || campaigns.length === 0) {
    box.innerHTML = '<p class="text-xs text-slate-400">No active syndicated campaigns detected yet.</p>';
    return;
  }

  campaigns.forEach(c => {
    box.innerHTML += `
      <div class="bg-tint/50 border border-accent rounded-xl p-4 space-y-2">
        <div class="flex items-center justify-between">
          <span class="mono text-xs font-extrabold text-redflag bg-white border border-red-200 px-2 py-0.5 rounded shadow-sm">${c.campaign_id}</span>
          <span class="text-xs text-slate-600 font-semibold">${c.report_count} Incident Reports</span>
        </div>
        <h4 class="text-sm font-extrabold text-slate-900">${c.name}</h4>
        <div class="flex flex-wrap gap-2 text-xs">
          <span class="bg-white text-slate-700 border border-accent px-2 py-0.5 rounded font-medium">Scam: ${c.scam_category}</span>
          ${c.impersonated_brand ? `<span class="bg-red-50 text-redflag border border-red-200 px-2 py-0.5 rounded font-semibold">Mimics: ${c.impersonated_brand}</span>` : ''}
          <span class="bg-white text-slate-700 border border-accent px-2 py-0.5 rounded font-medium">${c.threat_indicators_count} Identifiers</span>
        </div>
        ${c.associated_locations.length > 0 ? `<p class="text-[11px] text-slate-500 font-medium">Reported in: ${c.associated_locations.join(', ')}</p>` : ''}
      </div>
    `;
  });
}

// Entity Deep Investigation
async function runInvestigation() {
  const q = document.getElementById('inv-query').value.trim();
  if (!q) return;

  try {
    const res = await fetch(`/api/v1/graph/investigate/${encodeURIComponent(q)}`);
    const data = await res.json();

    const resBox = document.getElementById('inv-result');
    resBox.classList.remove('hidden');

    if (!data.found) {
      document.getElementById('inv-entity-name').textContent = q;
      document.getElementById('inv-entity-type').textContent = "Not Found in Threat Graph";
      document.getElementById('inv-connections').textContent = "0";
      document.getElementById('inv-campaigns-box').classList.add('hidden');
      document.getElementById('inv-network-canvas').innerHTML = '<div class="h-full flex items-center justify-center text-xs text-slate-400">No records found for this indicator.</div>';
      return;
    }

    document.getElementById('inv-entity-name').textContent = data.queried_entity;
    document.getElementById('inv-entity-type').textContent = data.entity_type || 'INDICATOR';
    document.getElementById('inv-connections').textContent = data.connection_count;

    const campBox = document.getElementById('inv-campaigns-box');
    if (data.connected_campaign_ids && data.connected_campaign_ids.length > 0) {
      campBox.classList.remove('hidden');
      document.getElementById('inv-campaigns-list').textContent = data.connected_campaign_ids.join(', ');
    } else {
      campBox.classList.add('hidden');
    }

    renderNetwork(data.subgraph, 'inv-network-canvas');
  } catch (err) {
    alert("Investigation error: " + err.message);
  }
}
