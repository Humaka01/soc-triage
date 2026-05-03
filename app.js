"use strict";
/* ═══════════════════════════════════════════════════
   SOC TRIAGE — app.js
   No config.js — keys entered per-session via modal
═══════════════════════════════════════════════════ */

// ── Session keys (in-memory only) ─────────────────
const KEYS = { vt: "", abuse: "" };

// ── Cloudflare Worker URL ─────────────────────────────────
const WORKER = "wild-union-9040.vodislavimad.workers.dev";

async function workerFetch(path, headers = {}) {
  const res = await fetch(WORKER + path, {
    headers,
    signal: AbortSignal.timeout(12000),
  });
  return res;
}

// ── State ──────────────────────────────────────────
const S = {
  tickets: [],
  allIps: [],
  allUrls: [],
  allDomains: [],
  allHashes: [],
  activeTicket: null,
  activeTab: "tickets",
  filters: { q: "", status: "", priority: "", severity: "" },
  cache: {}, // ioc → { vt, abuse, cf, err }
  pending: new Set(),
  aborted: false,
  running: false,
};

// ── OSINT sources ──────────────────────────────────
const OSINT = {
  ip: [
    {
      l: "VirusTotal",
      u: (v) => `https://www.virustotal.com/gui/ip-address/${v}/details`,
    },
    { l: "AbuseIPDB", u: (v) => `https://www.abuseipdb.com/check/${v}` },
    {
      l: "Talos",
      u: (v) =>
        `https://talosintelligence.com/reputation_center/lookup?search=${v}`,
    },
    { l: "CrowdSec", u: (v) => `https://app.crowdsec.net/analysis/ip/${v}` },
    { l: "Shodan", u: (v) => `https://www.shodan.io/host/${v}` },
    {
      l: "IPQualityScore",
      u: (v) => `https://www.ipqualityscore.com/free-ip-lookup/${v}`,
    },
  ],
  url: [
    {
      l: "VirusTotal",
      u: (v) =>
        `https://www.virustotal.com/gui/url/${encodeURIComponent(v)}/detection`,
    },
    {
      l: "URLScan",
      u: (v) => `https://urlscan.io/search/#${encodeURIComponent(v)}`,
    },
    {
      l: "Talos",
      u: (v) =>
        `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(v)}`,
    },
    {
      l: "Kaspersky",
      u: (v) => `https://opentip.kaspersky.com/${encodeURIComponent(v)}`,
    },
  ],
  domain: [
    {
      l: "VirusTotal",
      u: (v) => `https://www.virustotal.com/gui/domain/${v}/details`,
    },
    {
      l: "URLScan",
      u: (v) => `https://urlscan.io/search/#${encodeURIComponent(v)}`,
    },
    {
      l: "Talos",
      u: (v) =>
        `https://talosintelligence.com/reputation_center/lookup?search=${v}`,
    },
    { l: "CF Radar", u: (v) => `https://radar.cloudflare.com/${v}` },
    {
      l: "Kaspersky",
      u: (v) => `https://opentip.kaspersky.com/${encodeURIComponent(v)}`,
    },
  ],
  hash: [
    {
      l: "VirusTotal",
      u: (v) => `https://www.virustotal.com/gui/file/${v}/detection`,
    },
    { l: "Kaspersky", u: (v) => `https://opentip.kaspersky.com/${v}` },
    {
      l: "MalwareBazaar",
      u: (v) => `https://bazaar.abuse.ch/browse.php?search=sha256%3A${v}`,
    },
  ],
};

// ── Trusted domains ────────────────────────────────
const TRUSTED = new Set([
  "microsoft.com",
  "outlook.com",
  "protection.outlook.com",
  "office.com",
  "office365.com",
  "microsoftonline.com",
  "live.com",
  "azure.com",
  "azure-api.net",
  "mails.microsoft.com",
  "cdn-dynmedia-1.microsoft.com",
  "windows.net",
  "google.com",
  "googleapis.com",
  "gstatic.com",
  "gmail.com",
  "googleusercontent.com",
  "apple.com",
  "icloud.com",
  "amazon.com",
  "amazonaws.com",
  "cloudfront.net",
  "github.com",
  "github.io",
  "slack.com",
  "zoom.us",
  "dropbox.com",
  "cloudflare.com",
  "cloudflare.net",
  "akamai.net",
  "akamaized.net",
  "linkedin.com",
  "twitter.com",
  "x.com",
  "facebook.com",
  "reddit.com",
]);
const isTrusted = (d) => {
  if (!d) return false;
  const dl = d.toLowerCase();
  return TRUSTED.has(dl) || [...TRUSTED].some((t) => dl.endsWith("." + t));
};

// ── DOM helpers ────────────────────────────────────
const $ = (id) => document.getElementById(id);
const esc = (s) =>
  s
    ? String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
    : "";
const trunc = (s, n) => (s && s.length > n ? s.slice(0, n) + "…" : s || "");

// ── DOM refs ───────────────────────────────────────
const elModal = $("keysModal");
const elKeyVT = $("keyVT");
const elKeyAbuse = $("keyAbuse");
const elModalCancel = $("modalCancel");
const elModalGo = $("modalGo");
const elFileInput = $("fileInput");
const elFilenameTag = $("filenameTag");
const elManualToggle = $("manualToggle");
const elManualDrawer = $("manualDrawer");
const elManualType = $("manualType");
const elManualText = $("manualText");
const elManualProc = $("manualProcess");
const elManualClear = $("manualClear");
const elResetBtn = $("resetBtn");
const elAnalyzeBtn = $("analyzeBtn");
const elStopBtn = $("stopBtn");
const elStatusPill = $("statusPill");
const elStatusText = $("statusText");
const elClock = $("clock");
const elProgressArea = $("progressArea");
const elProgFill = $("progFill");
const elProgText = $("progText");
const elSearchInput = $("searchInput");
const elFStatus = $("filterStatus");
const elFPriority = $("filterPriority");
const elFSeverity = $("filterSeverity");
const elTicketList = $("ticketList");
const elDetailPane = $("detailPane");
const elAnalyticsGrid = $("analyticsGrid");
const elIpList = $("ipList");
const elDomainList = $("domainList");
const elUrlList = $("urlList");
const elHashList = $("hashList");

// ── Clock ──────────────────────────────────────────
setInterval(() => {
  elClock.textContent = new Date().toTimeString().slice(0, 8);
}, 1000);
elClock.textContent = new Date().toTimeString().slice(0, 8);

// ── Modal ──────────────────────────────────────────
function openModal() {
  elModal.classList.add("open");
  elModal.style.display = "flex";
  elKeyVT.focus();
}
function closeModal() {
  elModal.classList.remove("open");
  elModal.style.display = "none";
}

elModalCancel.addEventListener("click", closeModal);
elModal.addEventListener("click", (e) => {
  if (e.target === elModal) closeModal();
});

// Eye toggle
document.querySelectorAll(".btn-eye").forEach((btn) => {
  btn.addEventListener("click", () => {
    const inp = $(btn.dataset.for);
    inp.type = inp.type === "password" ? "text" : "password";
    btn.innerHTML =
      inp.type === "text"
        ? `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`
        : `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
  });
});

elModalGo.addEventListener("click", () => {
  const vt = elKeyVT.value.trim();
  const abuse = elKeyAbuse.value.trim();
  if (!vt && !abuse) {
    toast("Enter at least one API key (VirusTotal or AbuseIPDB).", "err");
    return;
  }
  KEYS.vt = vt;
  KEYS.abuse = abuse;
  closeModal();
  startAnalysis();
});

// ── Tab / nav ──────────────────────────────────────
function switchTab(tab) {
  document
    .querySelectorAll(".snav")
    .forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  document
    .querySelectorAll(".tab-view")
    .forEach((v) => v.classList.toggle("active", v.id === `view-${tab}`));
  document
    .querySelectorAll(".ctr")
    .forEach((c) => c.classList.toggle("active", c.dataset.tab === tab));
  S.activeTab = tab;
}

document
  .querySelectorAll(".snav")
  .forEach((b) => b.addEventListener("click", () => switchTab(b.dataset.tab)));
document
  .querySelectorAll(".ctr")
  .forEach((c) => c.addEventListener("click", () => switchTab(c.dataset.tab)));

// ── Filters ────────────────────────────────────────
elSearchInput.addEventListener("input", () => {
  S.filters.q = elSearchInput.value.toLowerCase();
  renderTickets();
});
elFStatus.addEventListener("change", () => {
  S.filters.status = elFStatus.value;
  renderTickets();
});
elFPriority.addEventListener("change", () => {
  S.filters.priority = elFPriority.value;
  renderTickets();
});
elFSeverity.addEventListener("change", () => {
  S.filters.severity = elFSeverity.value;
  renderTickets();
});

// ── File import ────────────────────────────────────
elFileInput.addEventListener("change", () => {
  const files = Array.from(elFileInput.files);
  if (!files.length) return;
  elFilenameTag.textContent = files.map((f) => f.name).join(" · ");
  Promise.all(files.map((f) => readText(f))).then((contents) => {
    contents.forEach((text, i) => {
      const name = files[i].name.toLowerCase();
      if (name.endsWith(".csv")) processCSV(text);
      else processText(text, "auto");
    });
  });
});

function readText(file) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = (e) => res(e.target.result);
    r.onerror = () => rej(r.error);
    r.readAsText(file, "UTF-8");
  });
}

// ── Manual input ───────────────────────────────────
elManualToggle.addEventListener("click", () => {
  elManualDrawer.classList.toggle("open");
});
elManualClear.addEventListener("click", () => {
  elManualText.value = "";
});
elManualProc.addEventListener("click", () => {
  const raw = elManualText.value.trim();
  if (!raw) {
    toast("Enter at least one IOC.", "warn");
    return;
  }
  processText(raw, elManualType.value);
  toast("Manual input processed.", "ok");
});

// ── Reset ──────────────────────────────────────────
elResetBtn.addEventListener("click", resetAll);

// ── Analyze button ─────────────────────────────────
elAnalyzeBtn.addEventListener("click", () => {
  if (S.running) return;
  openModal();
});

// ── Stop button ────────────────────────────────────
elStopBtn.addEventListener("click", () => {
  S.aborted = true;
  apiQueue.length = 0;
  toast("Analysis stopped.", "warn");
  setRunning(false);
});

// ── CSV parser ─────────────────────────────────────
function parseCSVRows(text) {
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const rows = [];
  let inQ = false,
    cur = "",
    cols = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') {
      if (inQ && text[i + 1] === '"') {
        cur += '"';
        i++;
      } else inQ = !inQ;
    } else if (ch === "," && !inQ) {
      cols.push(cur);
      cur = "";
    } else if ((ch === "\n" || ch === "\r") && !inQ) {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      cols.push(cur);
      cur = "";
      rows.push(cols);
      cols = [];
    } else cur += ch;
  }
  if (cur || cols.length) {
    cols.push(cur);
    rows.push(cols);
  }
  return rows;
}

function processCSV(raw) {
  const rows = parseCSVRows(raw);
  if (rows.length < 2) {
    toast("CSV is empty or invalid.", "err");
    return;
  }
  const headers = rows[0].map((h) => h.trim());
  const col = (name) => headers.indexOf(name);
  const tickets = [];

  for (let i = 1; i < rows.length; i++) {
    const r = rows[i];
    if (r.every((c) => !c.trim())) continue;
    const get = (name) => (r[col(name)] || "").trim();

    const tiIPs = get("Custom field (Threat Intelligence | IP Indicators)");
    const tiDoms = get(
      "Custom field (Threat Intelligence | Domain Indicators)",
    );
    const tiURLs = get("Custom field (Threat Intelligence | URL Indicators)");
    const tiFiles = get("Custom field (Threat Intelligence | File Indicators)");
    const desc = get("Description");

    const ips = extractIPs(tiIPs || desc);
    const urls = extractURLs(tiURLs || desc);
    const domains = extractDomains(tiDoms || desc, urls);
    const hashes = extractHashes(tiFiles || desc);

    const rawTactics = get("Custom field (Tactics)");
    const tactics = rawTactics
      ? rawTactics
          .replace(/['"]/g, "")
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean)
      : [];

    tickets.push({
      key: get("Issue key") || `ROW-${i}`,
      summary: get("Summary"),
      issueType: get("Issue Type"),
      status: get("Status"),
      priority: get("Priority"),
      assignee: get("Assignee"),
      reporter: get("Reporter"),
      created: get("Created"),
      updated: get("Updated"),
      resolved: get("Resolved"),
      description: desc,
      sevSOC: get("Custom field (Severity SOC)"),
      sevDEV: get("Custom field (Severity DEV)"),
      tactics,
      sentinelARM: get("Custom field (Sentinel ARM ID)"),
      sentinelTitle: get("Custom field (Sentinel Incident Title)"),
      summaryInv: get("Custom field (Summary Investigation)"),
      procLink: get("Custom field (Procedure Link)"),
      requestType: get("Custom field (Request Type)"),
      statusCat: get("Status Category"),
      ips,
      urls,
      domains,
      hashes,
    });
  }

  if (!tickets.length) {
    toast("No valid tickets found in CSV.", "err");
    return;
  }
  ingestTickets(tickets);
  toast(`${tickets.length} tickets imported from CSV.`, "ok");
}

// ── Plain text / manual processing ─────────────────
function processText(text, typeHint = "auto") {
  // Create a single synthetic "ticket" for text file imports
  const ips = typeHint === "ip" ? parseManual(text, "ip") : extractIPs(text);
  const urls =
    typeHint === "url" ? parseManual(text, "url") : extractURLs(text);
  const domains =
    typeHint === "domain"
      ? parseManual(text, "domain")
      : extractDomains(text, urls);
  const hashes =
    typeHint === "hash" ? parseManual(text, "hash") : extractHashes(text);

  if (!ips.length && !urls.length && !domains.length && !hashes.length) {
    toast("No IOCs detected in input.", "warn");
    return;
  }

  // If no tickets loaded yet, create a virtual ticket
  if (!S.tickets.length) {
    ingestTickets([
      {
        key: "MANUAL-1",
        summary: "Manual Input",
        issueType: "Manual",
        status: "",
        priority: "",
        assignee: "",
        reporter: "",
        created: "",
        updated: "",
        resolved: "",
        description: text,
        sevSOC: "",
        sevDEV: "",
        tactics: [],
        sentinelARM: "",
        sentinelTitle: "",
        summaryInv: "",
        procLink: "",
        requestType: "",
        statusCat: "",
        ips,
        urls,
        domains,
        hashes,
      },
    ]);
  } else {
    // Add IOCs to the global deduplicated lists
    const add = (arr, newItems, ticketKey) => {
      newItems.forEach((v) => {
        const ex = arr.find((x) => x.value === v);
        if (ex) {
          if (!ex.tickets.includes(ticketKey)) ex.tickets.push(ticketKey);
        } else arr.push({ value: v, tickets: [ticketKey] });
      });
    };
    add(S.allIps, ips, "MANUAL");
    add(S.allDomains, domains, "MANUAL");
    add(S.allUrls, urls, "MANUAL");
    add(S.allHashes, hashes, "MANUAL");
    updateCounters();
    renderIOCTabs();
  }
}

function parseManual(text, type) {
  const items = text
    .split(/[,\n\r;\t]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (type === "ip") return [...new Set(items.filter(isValidIP))];
  if (type === "url")
    return [...new Set(items.filter((s) => s.startsWith("http")))];
  if (type === "domain")
    return [
      ...new Set(items.filter((s) => /^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(s))),
    ];
  if (type === "hash")
    return [...new Set(items.filter((s) => /^[A-Fa-f0-9]{32,128}$/.test(s)))];
  return [];
}

function ingestTickets(tickets) {
  S.tickets = [...S.tickets, ...tickets];
  S.allIps = dedup([
    ...S.allIps,
    ...tickets.flatMap((t) =>
      t.ips.map((v) => ({ value: v, ticketKey: t.key })),
    ),
  ]);
  S.allUrls = dedup([
    ...S.allUrls,
    ...tickets.flatMap((t) =>
      t.urls.map((v) => ({ value: v, ticketKey: t.key })),
    ),
  ]);
  S.allDomains = dedup([
    ...S.allDomains,
    ...tickets.flatMap((t) =>
      t.domains.map((v) => ({ value: v, ticketKey: t.key })),
    ),
  ]);
  S.allHashes = dedup([
    ...S.allHashes,
    ...tickets.flatMap((t) =>
      t.hashes.map((v) => ({ value: v, ticketKey: t.key })),
    ),
  ]);

  populateFilters();
  updateCounters();
  renderTickets();
  renderIOCTabs();
  renderAnalytics();

  elStatusPill.classList.add("live");
  elStatusText.textContent = `${S.tickets.length} ticket${S.tickets.length !== 1 ? "s" : ""} loaded`;
  elAnalyzeBtn.disabled = false;
}

// ── IOC extractors ─────────────────────────────────
function extractIPs(text) {
  const re = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  return [...new Set((text.match(re) || []).filter(isValidIP))];
}
function isValidIP(ip) {
  return ip.split(".").every((n) => +n >= 0 && +n <= 255);
}

function extractURLs(text) {
  const re = /https?:\/\/[^\s"'<>\]\\)]+/gi;
  return [
    ...new Set((text.match(re) || []).map((u) => u.replace(/[.,;)]+$/, ""))),
  ];
}

function extractDomains(text, urls) {
  const urlHosts = urls
    .map((u) => {
      try {
        return new URL(u).hostname.toLowerCase();
      } catch {
        return null;
      }
    })
    .filter(Boolean);
  const re = /\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
  const plain = (text.match(re) || [])
    .map((d) => d.toLowerCase())
    .filter((d) => !urlHosts.includes(d) && !extractIPs(d).length);
  return [...new Set([...urlHosts, ...plain])].filter((d) => d.includes("."));
}

function extractHashes(text) {
  const pats = [
    /\b[A-Fa-f0-9]{128}\b/g,
    /\b[A-Fa-f0-9]{64}\b/g,
    /\b[A-Fa-f0-9]{40}\b/g,
    /\b[A-Fa-f0-9]{32}\b/g,
  ];
  const r = new Set();
  pats.forEach((p) => (text.match(p) || []).forEach((h) => r.add(h)));
  return [...r];
}

function dedup(arr) {
  const m = new Map();
  arr.forEach((item) => {
    const key = item.value || item;
    const ticketKey = item.ticketKey;
    if (!m.has(key)) m.set(key, { value: key, tickets: [] });
    if (ticketKey && !m.get(key).tickets.includes(ticketKey))
      m.get(key).tickets.push(ticketKey);
  });
  return [...m.values()];
}

// ── Filters / counters ─────────────────────────────
function populateFilters() {
  const uniq = (arr) => [...new Set(arr.filter(Boolean))].sort();
  const fill = (sel, vals, lbl) => {
    const cur = sel.value;
    sel.innerHTML = `<option value="">${lbl}</option>`;
    vals.forEach((v) => {
      const o = document.createElement("option");
      o.value = v;
      o.textContent = v;
      if (v === cur) o.selected = true;
      sel.appendChild(o);
    });
  };
  fill(elFStatus, uniq(S.tickets.map((t) => t.status)), "Status");
  fill(elFPriority, uniq(S.tickets.map((t) => t.priority)), "Priority");
  fill(elFSeverity, uniq(S.tickets.map((t) => t.sevSOC)), "Severity");
}

function updateCounters() {
  $("cntTickets").textContent = S.tickets.length;
  $("cntIps").textContent = S.allIps.length;
  $("cntDomains").textContent = S.allDomains.length;
  $("cntUrls").textContent = S.allUrls.length;
  $("cntHashes").textContent = S.allHashes.length;
  $("cntAnalyzed").textContent = Object.keys(S.cache).length;
}

// ── Render tickets ─────────────────────────────────
function filteredTickets() {
  const { q, status, priority, severity } = S.filters;
  return S.tickets.filter((t) => {
    if (status && t.status !== status) return false;
    if (priority && t.priority !== priority) return false;
    if (severity && t.sevSOC !== severity) return false;
    if (q) {
      const blob = [
        t.key,
        t.summary,
        t.description,
        t.assignee,
        ...t.ips,
        ...t.urls,
        ...t.domains,
        ...t.hashes,
        ...t.tactics,
      ]
        .join(" ")
        .toLowerCase();
      if (!blob.includes(q)) return false;
    }
    return true;
  });
}

function renderTickets() {
  const list = filteredTickets();
  if (!list.length) {
    elTicketList.innerHTML = `<div class="splash"><div class="splash-mark">◈</div><div class="splash-title">No tickets match</div><div class="splash-body">Try adjusting your filters or search query.</div></div>`;
    return;
  }
  elTicketList.innerHTML = list.map(buildTicketCard).join("");
  elTicketList.querySelectorAll(".tkt").forEach((card) => {
    card.addEventListener("click", () => {
      const t = S.tickets.find((x) => x.key === card.dataset.key);
      if (!t) return;
      elTicketList
        .querySelectorAll(".tkt")
        .forEach((c) => c.classList.remove("sel"));
      card.classList.add("sel");
      S.activeTicket = t.key;
      renderDetailPane(t);
    });
  });
}

function buildTicketCard(t) {
  const total =
    t.ips.length + t.urls.length + t.domains.length + t.hashes.length;
  const isActive = S.activeTicket === t.key;
  const sevCls =
    { High: "thr-high", Critical: "thr-high", Medium: "thr-med" }[t.sevSOC] ||
    "";

  const chips = [
    ...t.ips.slice(0, 2).map((v) => `<span class="chip ip">${esc(v)}</span>`),
    ...t.domains
      .slice(0, 2)
      .map((v) => `<span class="chip domain">${esc(v)}</span>`),
    ...t.urls
      .slice(0, 1)
      .map((v) => `<span class="chip url">${esc(trunc(v, 38))}</span>`),
    ...t.hashes
      .slice(0, 1)
      .map((v) => `<span class="chip hash">${esc(v.slice(0, 12))}…</span>`),
  ];
  const extra = total - chips.length;
  if (extra > 0) chips.push(`<span class="chip more">+${extra} more</span>`);

  const verdictRows = t.ips
    .slice(0, 2)
    .map((ip) => {
      const cached = S.cache[ip];
      if (!cached && !S.running) return "";
      return `<div class="vrow"><span class="vrow-ip">${esc(ip)}</span><span data-v="${esc(ip)}">${verdictBadge(cached)}</span></div>`;
    })
    .filter(Boolean)
    .join("");

  const tactics = t.tactics
    .slice(0, 3)
    .map((tac) => `<span class="tactic">${esc(tac)}</span>`)
    .join("");

  return `<div class="tkt ${sevCls} ${isActive ? "sel" : ""}" data-key="${esc(t.key)}">
    <div class="tkt-top">
      <div style="display:flex;gap:8px;align-items:flex-start;flex:1;min-width:0">
        <span class="tkt-key">${esc(t.key)}</span>
        <span class="tkt-title">${esc(t.summary)}</span>
      </div>
      <div class="tkt-badges">
        ${statusBadge(t.status)}${priorityBadge(t.priority)}
        ${t.sevSOC ? `<span class="badge b-${t.sevSOC.toLowerCase()}">${esc(t.sevSOC)}</span>` : ""}
      </div>
    </div>
    <div class="tkt-meta">
      <span>👤 ${esc(t.assignee || "Unassigned")}</span>
      <span>📅 ${esc((t.created || "").split(" ")[0] || "—")}</span>
      ${total ? `<span>🎯 ${total} IOC${total !== 1 ? "s" : ""}</span>` : ""}
      ${t.sentinelARM ? `<span>🔷 Sentinel</span>` : ""}
    </div>
    ${chips.length ? `<div class="tkt-iocs">${chips.join("")}</div>` : ""}
    ${verdictRows ? `<div class="tkt-verdicts">${verdictRows}</div>` : ""}
    ${tactics ? `<div class="tkt-tactics">${tactics}</div>` : ""}
  </div>`;
}

// ── Detail pane ────────────────────────────────────
function renderDetailPane(t) {
  const fields = [
    ["Issue Type", t.issueType],
    ["Status", t.status],
    ["Priority", t.priority],
    ["Severity SOC", t.sevSOC],
    ["Severity DEV", t.sevDEV],
    ["Assignee", t.assignee],
    ["Reporter", t.reporter],
    ["Created", t.created],
    ["Updated", t.updated],
    ["Resolved", t.resolved],
    ["Request Type", t.requestType],
    ["Sentinel ARM", t.sentinelARM],
    ["Sentinel Title", t.sentinelTitle],
    ["Tactics", t.tactics.join(", ")],
    ["Procedure", t.procLink],
    ["Summary Inv.", t.summaryInv],
  ].filter(([, v]) => v && v !== "NaN");

  const fieldHtml = fields
    .map(([lbl, val]) => {
      let disp = esc(val);
      if (lbl === "Procedure" && val.startsWith("http"))
        disp = `<a href="${esc(val)}" target="_blank" rel="noreferrer">Open ↗</a>`;
      if (lbl === "Sentinel ARM") {
        const url = `https://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident/${val}`;
        disp = `<a href="${esc(url)}" target="_blank" rel="noreferrer">${esc(val)}</a>`;
      }
      return `<div class="detail-row"><span class="detail-lbl">${esc(lbl)}</span><span class="detail-val">${disp}</span></div>`;
    })
    .join("");

  const iocSecs = [
    { lbl: "IP Indicators", items: t.ips, type: "ip" },
    { lbl: "URL Indicators", items: t.urls, type: "url" },
    { lbl: "Domain Indicators", items: t.domains, type: "domain" },
    { lbl: "File Hashes", items: t.hashes, type: "hash" },
  ].filter((s) => s.items.length);

  const iocHtml = iocSecs
    .map(
      (sec) => `
    <div class="detail-sec">
      <div class="detail-sec-title">${esc(sec.lbl)}</div>
      <div class="detail-ioc-list">
        ${sec.items
          .map((v) => {
            const cached = S.cache[v];
            const vhtml = `<div class="detail-verdict" data-v="${esc(v)}">${verdictBadge(cached)}</div>`;
            return `<div class="detail-ioc-item">
            <div class="detail-ioc-v">${esc(v)}</div>
            ${vhtml}
            <div class="detail-ioc-links">
              ${(OSINT[sec.type] || []).map((s) => `<a class="osint-a" href="${s.u(v)}" target="_blank" rel="noreferrer">${esc(s.l)}</a>`).join("")}
            </div>
          </div>`;
          })
          .join("")}
      </div>
    </div>`,
    )
    .join("");

  const descClean = (t.description || "Nu există descriere.")
    .replace(/\[Link\|([^\]]+)\]/g, "$1")
    .replace(/\*\s+/g, "• ")
    .replace(/\\n/g, "\n");

  elDetailPane.innerHTML = `<div class="detail-content">
    <div class="detail-hdr">
      <div class="detail-dkey">${esc(t.key)} · ${esc(t.issueType || "")}</div>
      <div class="detail-dtitle">${esc(t.summary)}</div>
      <div class="detail-dbadges">${statusBadge(t.status)}${priorityBadge(t.priority)}${t.sevSOC ? `<span class="badge b-${t.sevSOC.toLowerCase()}">${esc(t.sevSOC)}</span>` : ""}</div>
    </div>
    <div class="detail-sec"><div class="detail-sec-title">Ticket Details</div>${fieldHtml}</div>
    ${iocHtml}
    <div class="detail-sec"><div class="detail-sec-title">Description</div><div class="detail-desc">${esc(descClean)}</div></div>
  </div>`;
}

// ── IOC tabs ───────────────────────────────────────
function renderIOCTabs() {
  elIpList.innerHTML = buildIOCGrid(S.allIps, "ip");
  elDomainList.innerHTML = buildIOCGrid(S.allDomains, "domain");
  elUrlList.innerHTML = buildIOCGrid(S.allUrls, "url");
  elHashList.innerHTML = buildIOCGrid(S.allHashes, "hash");
}

function buildIOCGrid(items, type) {
  if (!items.length)
    return `<div class="splash"><div class="splash-mark">◈</div><div class="splash-title">No ${type} indicators</div></div>`;
  return items
    .map((item) => {
      const { value: val, tickets: refs } = item;
      const trusted =
        (type === "domain" || type === "url") &&
        isTrusted(
          type === "url"
            ? (() => {
                try {
                  return new URL(val).hostname;
                } catch {
                  return val;
                }
              })()
            : val,
        );
      const cached = S.cache[val];
      const vhtml = trusted
        ? '<span class="verd v-trust">Trusted</span>'
        : `<span data-v="${esc(val)}">${verdictBadge(cached)}</span>`;

      return `<div class="ioc-row">
      <span class="ioc-typetag ${type}">${type.toUpperCase()}</span>
      <span class="ioc-val">${esc(val)}</span>
      ${vhtml}
      <span class="ioc-ref">${esc((refs || []).join(", "))}</span>
      <div class="ioc-links">
        ${(OSINT[type] || []).map((s) => `<a class="osint-a" href="${s.u(val)}" target="_blank" rel="noreferrer">${esc(s.l)}</a>`).join("")}
      </div>
    </div>`;
    })
    .join("");
}

// ── Analytics ──────────────────────────────────────
function renderAnalytics() {
  const t = S.tickets;
  if (!t.length) {
    elAnalyticsGrid.innerHTML = `<div class="splash"><div class="splash-mark">◈</div><div class="splash-title">Import data to see analytics</div></div>`;
    return;
  }
  const cnt = (arr, key) => {
    const m = {};
    arr.forEach((x) => {
      const v = x[key] || "Unknown";
      m[v] = (m[v] || 0) + 1;
    });
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  };
  const total =
    S.allIps.length +
    S.allUrls.length +
    S.allDomains.length +
    S.allHashes.length;
  const withIOC = t.filter(
    (x) =>
      x.ips.length + x.urls.length + x.domains.length + x.hashes.length > 0,
  ).length;
  const tacMap = {};
  t.flatMap((x) => x.tactics).forEach((tac) => {
    tacMap[tac] = (tacMap[tac] || 0) + 1;
  });
  const tacList = Object.entries(tacMap).sort((a, b) => b[1] - a[1]);
  const analyzed = Object.keys(S.cache).length;

  elAnalyticsGrid.innerHTML = `
    <div class="an-card full">
      <div class="an-title">Overview</div>
      <div class="an-stat-grid">
        <div class="an-stat"><div class="an-stat-val">${t.length}</div><div class="an-stat-lbl">Tickets</div></div>
        <div class="an-stat"><div class="an-stat-val">${total}</div><div class="an-stat-lbl">Total IOCs</div></div>
        <div class="an-stat"><div class="an-stat-val">${withIOC}</div><div class="an-stat-lbl">Tickets w/ IOCs</div></div>
        <div class="an-stat"><div class="an-stat-val">${analyzed}</div><div class="an-stat-lbl">IOCs Analyzed</div></div>
      </div>
    </div>
    <div class="an-card"><div class="an-title">By Status</div>${bc(cnt(t, "status"), t.length, { Open: "var(--green)", Reopened: "var(--orange)" })}</div>
    <div class="an-card"><div class="an-title">By Priority</div>${bc(cnt(t, "priority"), t.length, { P1: "var(--red)", P2: "var(--orange)", P3: "var(--yellow)", P4: "var(--cyan)" })}</div>
    <div class="an-card"><div class="an-title">By Severity SOC</div>${bc(cnt(t, "sevSOC"), t.length, { High: "var(--red)", Medium: "var(--orange)", Low: "var(--yellow)", Informational: "var(--cyan)" })}</div>
    <div class="an-card"><div class="an-title">IOC Breakdown</div>${bc(
      [
        ["IPs", S.allIps.length],
        ["Domains", S.allDomains.length],
        ["URLs", S.allUrls.length],
        ["Hashes", S.allHashes.length],
      ],
      total,
      {
        IPs: "var(--cyan)",
        Domains: "var(--yellow)",
        URLs: "var(--orange)",
        Hashes: "var(--purple)",
      },
    )}</div>
    <div class="an-card full"><div class="an-title">MITRE ATT&CK Tactics</div>${tacList.length ? bc(tacList, Math.max(...tacList.map((c) => c[1])), {}) : '<div style="color:var(--t4);font-size:11px">No tactics detected.</div>'}</div>
    <div class="an-card full"><div class="an-title">Top Assignees</div>${bc(cnt(t, "assignee").slice(0, 8), t.length, {})}</div>`;
}

function bc(entries, max, cmap) {
  if (!entries.length || !max)
    return '<div style="color:var(--t4);font-size:11px">—</div>';
  return entries
    .map(
      ([lbl, n]) => `
    <div class="bar-row">
      <div class="bar-lbl">${esc(lbl)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.max((n / max) * 100, 2).toFixed(1)}%;background:${cmap[lbl] || "var(--cyan)"}"></div></div>
      <div class="bar-n">${n}</div>
    </div>`,
    )
    .join("");
}

// ── Badge helpers ──────────────────────────────────
function statusBadge(s) {
  const m = {
    Open: "b-open",
    Reopened: "b-reopened",
    Closed: "b-closed",
    Resolved: "b-closed",
  };
  return s ? `<span class="badge ${m[s] || "b-closed"}">${esc(s)}</span>` : "";
}
function priorityBadge(p) {
  const m = { P1: "b-p1", P2: "b-p2", P3: "b-p3", P4: "b-p4" };
  return p ? `<span class="badge ${m[p] || "b-p4"}">${esc(p)}</span>` : "";
}

// ── Verdict badge builder ──────────────────────────
function verdictBadge(result) {
  if (!result) return `<span class="verd v-queue">Queued…</span>`;
  if (result.err)
    return `<span class="verd v-err" title="${esc(result.err)}">Error</span>`;
  const parts = [];
  if (result.vt) {
    const { malicious: m, suspicious: s, total: tot } = result.vt;
    const f = m + s;
    const cls = m >= 5 ? "v-hi" : m >= 1 || s >= 3 ? "v-med" : "v-clean";
    parts.push(
      `<span class="verd ${cls}" title="VirusTotal: ${f}/${tot} vendors">VT ${f}/${tot}</span>`,
    );
  }
  if (result.abuse) {
    const sc = result.abuse.score;
    const cls = sc >= 75 ? "v-hi" : sc >= 25 ? "v-med" : "v-clean";
    const tip =
      `AbuseIPDB: ${sc}% · ${result.abuse.isp || ""} · ${result.abuse.country || ""}`
        .replace(/· ·/g, "·")
        .trim();
    parts.push(
      `<span class="verd ${cls}" title="${esc(tip)}">Abuse ${sc}%</span>`,
    );
  }
  if (result.cf && result.cf.cats) {
    parts.push(
      `<span class="verd v-med" title="Cloudflare Radar">CF: ${esc(result.cf.cats)}</span>`,
    );
  }
  return parts.length
    ? parts.join("")
    : `<span class="verd v-queue">No data</span>`;
}

function patchBadges(val, result) {
  document.querySelectorAll(`[data-v="${CSS.escape(val)}"]`).forEach((el) => {
    el.innerHTML = verdictBadge(result);
  });
}

// ── API layer ──────────────────────────────────────
const apiQueue = [];
let queueRunning = false;

function enqueue(fn) {
  return new Promise((res, rej) => {
    apiQueue.push({ fn, res, rej });
    drain();
  });
}

async function drain() {
  if (queueRunning) return;
  queueRunning = true;
  while (apiQueue.length && !S.aborted) {
    const { fn, res, rej } = apiQueue.shift();
    try {
      res(await fn());
    } catch (e) {
      rej(e);
    }
    if (apiQueue.length && !S.aborted) await sleep(15000);
  }
  queueRunning = false;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function vtFetch(url) {
  if (!KEYS.vt) return null;
  // Convert full VT URL to worker route
  // https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4 → /vt/ip/1.2.3.4
  const route = url
    .replace("https://www.virustotal.com/api/v3/ip_addresses/", "/vt/ip/")
    .replace("https://www.virustotal.com/api/v3/domains/", "/vt/domain/")
    .replace("https://www.virustotal.com/api/v3/files/", "/vt/hash/");
  const res = await workerFetch(route, { "X-VT-Key": KEYS.vt });
  if (res.status === 404) return null;
  if (res.status === 429) throw new Error("VT rate limit — wait and retry");
  if (res.status === 401) throw new Error("VT key invalid");
  if (!res.ok) throw new Error(`VT HTTP ${res.status}`);
  return res.json();
}

async function abuseFetch(ip) {
  if (!KEYS.abuse) return null;
  const res = await workerFetch(`/abuse/${ip}`, { "X-Abuse-Key": KEYS.abuse });
  if (res.status === 429) throw new Error("AbuseIPDB rate limit");
  if (res.status === 401) throw new Error("AbuseIPDB key invalid");
  if (!res.ok) throw new Error(`AbuseIPDB HTTP ${res.status}`);
  return res.json();
}

// cfFetch removed — Cloudflare Radar blocks browser CORS requests.
// The Cloudflare OSINT link still opens in a new tab.

function parseVT(data) {
  if (!data?.data?.attributes?.last_analysis_stats) return null;
  const s = data.data.attributes.last_analysis_stats;
  return {
    malicious: s.malicious || 0,
    suspicious: s.suspicious || 0,
    total: Object.values(s).reduce((a, b) => a + b, 0),
  };
}
function parseAbuse(data) {
  if (!data?.data) return null;
  return {
    score: data.data.abuseConfidenceScore,
    isp: data.data.isp || "",
    country: data.data.countryCode || "",
    reports: data.data.totalReports || 0,
  };
}
// parseCF removed — CF Radar not accessible from browser.

// ── Analysis runner ────────────────────────────────
function setRunning(v) {
  S.running = v;
  elAnalyzeBtn.style.display = v ? "none" : "flex";
  elStopBtn.style.display = v ? "flex" : "none";
  elProgressArea.style.display = v ? "block" : "none";
  if (!v) {
    elProgFill.style.width = "0%";
    elProgText.textContent = "";
  }
}

async function startAnalysis() {
  if (S.running) return;
  S.aborted = false;
  S.running = true;
  setRunning(true);

  // Worker handles all types: IPs (VT + AbuseIPDB), domains (VT), hashes (VT)
  const iocs = [
    ...S.allIps
      .filter((i) => !S.cache[i.value] && !S.pending.has(i.value))
      .map((i) => ({ value: i.value, type: "ip" })),
    ...S.allDomains
      .filter(
        (d) =>
          !isTrusted(d.value) && !S.cache[d.value] && !S.pending.has(d.value),
      )
      .map((d) => ({ value: d.value, type: "domain" })),
    ...S.allHashes
      .filter((h) => !S.cache[h.value] && !S.pending.has(h.value))
      .map((h) => ({ value: h.value, type: "hash" })),
  ];

  if (!iocs.length) {
    toast("All IOCs already analyzed or none found.", "warn");
    setRunning(false);
    return;
  }

  let done = 0;
  const total = iocs.length;
  elProgText.textContent = `0 / ${total} IOCs analyzed`;

  for (const ioc of iocs) {
    if (S.aborted) break;
    S.pending.add(ioc.value);

    await enqueue(async () => {
      if (S.aborted) return;
      const r = { vt: null, abuse: null, cf: null, err: null };
      try {
        if (ioc.type === "ip") {
          const [vt, ab] = await Promise.allSettled([
            vtFetch(
              `https://www.virustotal.com/api/v3/ip_addresses/${ioc.value}`,
            ),
            abuseFetch(ioc.value),
          ]);
          if (vt.status === "fulfilled") r.vt = parseVT(vt.value);
          if (ab.status === "fulfilled") r.abuse = parseAbuse(ab.value);
        } else if (ioc.type === "domain") {
          const vtData = await vtFetch(
            `https://www.virustotal.com/api/v3/domains/${ioc.value}`,
          );
          r.vt = parseVT(vtData);
        } else if (ioc.type === "hash") {
          const vt = await vtFetch(
            `https://www.virustotal.com/api/v3/files/${ioc.value}`,
          );
          r.vt = parseVT(vt);
        }
      } catch (e) {
        r.err = e.message;
        console.warn(`Lookup failed for ${ioc.value}:`, e.message);
      }

      S.cache[ioc.value] = r;
      S.pending.delete(ioc.value);
      done++;

      updateCounters();
      patchBadges(ioc.value, r);

      const pct = Math.round((done / total) * 100);
      elProgFill.style.width = pct + "%";
      elProgText.textContent = `${done} / ${total} IOCs analyzed`;
      elStatusText.textContent = `Analyzing: ${done}/${total}`;

      // Refresh detail pane if this IOC belongs to open ticket
      if (S.activeTicket) {
        const active = S.tickets.find((t) => t.key === S.activeTicket);
        if (
          active &&
          [...active.ips, ...active.domains, ...active.hashes].includes(
            ioc.value,
          )
        )
          renderDetailPane(active);
      }
    });
  }

  setRunning(false);
  if (!S.aborted) {
    toast(
      `Analysis complete — ${done} IOC${done !== 1 ? "s" : ""} checked.`,
      "ok",
    );
    elStatusText.textContent = `${S.tickets.length} tickets · ${done} IOCs analyzed`;
    renderAnalytics();
  }
}

// ── Reset ──────────────────────────────────────────
function resetAll() {
  if (S.running) {
    S.aborted = true;
    apiQueue.length = 0;
    setRunning(false);
  }
  Object.assign(S, {
    tickets: [],
    allIps: [],
    allUrls: [],
    allDomains: [],
    allHashes: [],
    activeTicket: null,
    cache: {},
    pending: new Set(),
    aborted: false,
    running: false,
  });
  S.filters = { q: "", status: "", priority: "", severity: "" };
  elFileInput.value = "";
  elFilenameTag.textContent = "CSV or TXT — IPs, domains, URLs, hashes";
  elSearchInput.value = "";
  elManualText.value = "";
  elStatusPill.classList.remove("live");
  elStatusText.textContent = "No data loaded";
  elAnalyzeBtn.disabled = true;
  updateCounters();
  elTicketList.innerHTML = `<div class="splash"><div class="splash-mark">◈</div><div class="splash-title">No data loaded</div><div class="splash-body">Import a Jira CSV or a plain text file containing IPs, domains, URLs, or hashes — or use Manual Input above.</div></div>`;
  elDetailPane.innerHTML = `<div class="detail-empty"><span class="detail-empty-mark">◈</span><span class="detail-empty-msg">Select a ticket to inspect</span></div>`;
  elAnalyticsGrid.innerHTML = `<div class="splash"><div class="splash-mark">◈</div><div class="splash-title">Import data to see analytics</div></div>`;
  elIpList.innerHTML =
    elDomainList.innerHTML =
    elUrlList.innerHTML =
    elHashList.innerHTML =
      `<div class="splash"><div class="splash-mark">◈</div><div class="splash-title">No indicators</div></div>`;
  toast("Dashboard reset.", "ok");
}

// ── Toast ──────────────────────────────────────────
function toast(msg, type = "info") {
  const el = document.createElement("div");
  el.className = `toast ${type === "err" ? "err" : type === "ok" ? "ok" : type === "warn" ? "warn" : ""}`;
  el.textContent = msg;
  $("toastBox").appendChild(el);
  setTimeout(() => el.remove(), 3400);
}
