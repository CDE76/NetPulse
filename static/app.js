/**
 * Logique Frontend NetPulse IPAM — Scanner Réseau Local IPv4, Historique, Import CSV & Export PDF
 */

const state = {
  network: "192.168.1.0",
  mask: "255.255.255.0",
  subnetInfo: null,
  addresses: [],
  stats: null,
  lastScan: null,
  history: [],
  currentFilter: "used", // 'used' | 'dns' | 'known' | 'free' | 'all'
  searchQuery: "",
  isScanning: false,
  pollTimer: null,
};

// Références DOM
const elInputNetwork = document.getElementById("inputNetwork");
const elSelectMaskPreset = document.getElementById("selectMaskPreset");
const elInputMaskCustom = document.getElementById("inputMaskCustom");
const elChkResolveDns = document.getElementById("chkResolveDns");
const elChkScanPorts = document.getElementById("chkScanPorts");
const elSelectTimeout = document.getElementById("selectTimeout");
const elScanForm = document.getElementById("scanForm");
const elBtnStartScan = document.getElementById("btnStartScan");
const elBtnLoadSubnet = document.getElementById("btnLoadSubnet");
const elBtnQuickSaveSnapshot = document.getElementById("btnQuickSaveSnapshot");

const elInterfacesList = document.getElementById("interfacesList");
const elSavedSubnetsBar = document.getElementById("savedSubnetsBar");
const elSavedSubnetsList = document.getElementById("savedSubnetsList");
const elHeaderHistoryCount = document.getElementById("headerHistoryCount");

// Calculateur de sous-réseau
const elCalcCidr = document.getElementById("calcCidr");
const elCalcNetAddr = document.getElementById("calcNetAddr");
const elCalcNetmask = document.getElementById("calcNetmask");
const elCalcRange = document.getElementById("calcRange");
const elCalcBroadcast = document.getElementById("calcBroadcast");
const elCalcUsable = document.getElementById("calcUsable");

// Barre de progression
const elScanProgressPanel = document.getElementById("scanProgressPanel");
const elProgressPhase = document.getElementById("progressPhase");
const elProgressCounter = document.getElementById("progressCounter");
const elProgressActiveFound = document.getElementById("progressActiveFound");
const elProgressDnsFound = document.getElementById("progressDnsFound");
const elProgressElapsed = document.getElementById("progressElapsed");
const elProgressBarFill = document.getElementById("progressBarFill");

// KPIs
const elKpiOnlineCount = document.getElementById("kpiOnlineCount");
const elKpiUtilizationPct = document.getElementById("kpiUtilizationPct");
const elKpiUtilizationBar = document.getElementById("kpiUtilizationBar");
const elKpiDnsCount = document.getElementById("kpiDnsCount");
const elKpiDnsRatio = document.getElementById("kpiDnsRatio");
const elKpiReservedCount = document.getElementById("kpiReservedCount");
const elKpiFreeCount = document.getElementById("kpiFreeCount");
const elKpiTotalUsable = document.getElementById("kpiTotalUsable");
const elKpiLastScanInfo = document.getElementById("kpiLastScanInfo");

// Grille & Tableau
const elGridSubnetTitle = document.getElementById("gridSubnetTitle");
const elIpGridContainer = document.getElementById("ipGridContainer");
const elIpamTableBody = document.getElementById("ipamTableBody");
const elFilterTabs = document.getElementById("filterTabs");
const elInputSearch = document.getElementById("inputSearch");

const elTabCountUsed = document.getElementById("tabCountUsed");
const elTabCountDns = document.getElementById("tabCountDns");
const elTabCountKnown = document.getElementById("tabCountKnown");
const elTabCountFree = document.getElementById("tabCountFree");
const elTabCountAll = document.getElementById("tabCountAll");

// Modal 1 : Édition IP
const elModalBackdrop = document.getElementById("ipModalBackdrop");
const elModalIpTitle = document.getElementById("modalIpTitle");
const elModalStatusBadge = document.getElementById("modalStatusBadge");
const elModalDnsVal = document.getElementById("modalDnsVal");
const elModalMacVal = document.getElementById("modalMacVal");
const elModalVendorVal = document.getElementById("modalVendorVal");
const elModalPingVal = document.getElementById("modalPingVal");
const elModalMethodVal = document.getElementById("modalMethodVal");
const elModalLastSeenVal = document.getElementById("modalLastSeenVal");
const elModalPortsList = document.getElementById("modalPortsList");
const elModalEditForm = document.getElementById("modalEditForm");
const elEditIp = document.getElementById("editIp");
const elEditCustomName = document.getElementById("editCustomName");
const elEditDnsName = document.getElementById("editDnsName");
const elEditStatus = document.getElementById("editStatus");
const elEditRole = document.getElementById("editRole");
const elEditNotes = document.getElementById("editNotes");

// Modal 2 : Historique & Sauvegardes
const elHistoryModalBackdrop = document.getElementById("historyModalBackdrop");
const elHistoryTableBody = document.getElementById("historyTableBody");
const elSaveSnapshotForm = document.getElementById("saveSnapshotForm");
const elInputSnapshotTitle = document.getElementById("inputSnapshotTitle");

// Modal 3 : Import CSV
const elImportModalBackdrop = document.getElementById("importModalBackdrop");
const elImportPlanForm = document.getElementById("importPlanForm");
const elInputImportFile = document.getElementById("inputImportFile");
const elChkReplaceSubnet = document.getElementById("chkReplaceSubnet");
const elImportFilePreview = document.getElementById("importFilePreview");

function showToast(message, type = "info") {
  const container = document.getElementById("toastContainer");
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 4200);
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// 1. Initialisation & Détection des interfaces du serveur
async function initApp() {
  bindEvents();
  try {
    const authRes = await fetch("/api/auth/me");
    if (authRes.status === 401) {
      window.location.href = "/login";
      return;
    }
    const authData = await authRes.json();
    if (authData.ok) {
      state.currentUser = authData.username;
      state.users = authData.users || [];
      const elUserLbl = document.getElementById("currentUserLabel");
      if (elUserLbl) elUserLbl.textContent = authData.username;
      renderUsersTable();
    }

    const res = await fetch("/api/interfaces");
    if (res.status === 401) {
      window.location.href = "/login";
      return;
    }
    const data = await res.json();

    renderInterfacesPills(data.interfaces || []);
    renderSavedSubnetsPills(data.saved_subnets || []);
    updateHistoryState(data.history || []);

    if (data.interfaces && data.interfaces.length > 0) {
      const primary = data.interfaces[0];
      const defaultNet = primary.prefixlen < 24 ? (primary.subnet_24 || primary.ip) : primary.network;
      const defaultMask = primary.prefixlen < 24 ? "255.255.255.0" : primary.netmask;
      setNetworkAndMaskInputs(defaultNet, defaultMask);
    } else if (data.saved_subnets && data.saved_subnets.length > 0) {
      const last = data.saved_subnets[0];
      setNetworkAndMaskInputs(last.network_address, last.netmask);
    }

    await updateSubnetPreview();
    await loadIpamData();

    if (data.scan_status && data.scan_status.is_scanning) {
      startPollingScan();
    }
  } catch (err) {
    showToast("Erreur lors de l'initialisation : " + err.message, "error");
  }
}

function setNetworkAndMaskInputs(networkIp, maskStr) {
  elInputNetwork.value = networkIp;
  elInputMaskCustom.value = maskStr;
  const matchingOption = Array.from(elSelectMaskPreset.options).find(
    (opt) => opt.value === maskStr
  );
  if (matchingOption) {
    elSelectMaskPreset.value = maskStr;
  }
  state.network = networkIp;
  state.mask = maskStr;
}

function renderInterfacesPills(interfaces) {
  elInterfacesList.innerHTML = "";
  if (!interfaces.length) {
    elInterfacesList.innerHTML = `<span class="text-muted">Aucune interface détectée</span>`;
    return;
  }

  interfaces.forEach((iface) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "iface-pill";
    btn.title = `Serveur IP: ${iface.ip} | Masque: ${iface.netmask} | Passerelle: ${iface.gateway || "N/A"}`;
    btn.innerHTML = `
      <span class="iface-dot"></span>
      <strong>${escapeHtml(iface.name)}</strong>
      <span class="mono">${escapeHtml(iface.cidr)}</span>
      <span class="text-muted">(IP: ${escapeHtml(iface.ip)})</span>
    `;
    btn.addEventListener("click", async () => {
      const defaultNet = iface.prefixlen < 24 ? (iface.subnet_24 || iface.ip) : iface.network;
      const defaultMask = iface.prefixlen < 24 ? "255.255.255.0" : iface.netmask;
      setNetworkAndMaskInputs(defaultNet, defaultMask);
      await updateSubnetPreview();
      await loadIpamData();
      showToast(`Interface sélectionnée : ${defaultNet} (Masque ${defaultMask})`, "info");
    });
    elInterfacesList.appendChild(btn);
  });
}

function renderSavedSubnetsPills(subnets) {
  if (!subnets || !subnets.length) {
    elSavedSubnetsBar.classList.add("hidden");
    return;
  }
  elSavedSubnetsBar.classList.remove("hidden");
  elSavedSubnetsList.innerHTML = "";

  subnets.forEach((sub) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "iface-pill";
    btn.title = `Dernière mise à jour : ${sub.last_scan_at || "N/A"}`;
    btn.innerHTML = `
      <span class="mono"><strong>${escapeHtml(sub.cidr)}</strong></span>
      <span class="text-success">${sub.last_active_count || 0} actives</span>
      <span class="text-accent">${sub.last_dns_count || 0} DNS</span>
    `;
    btn.addEventListener("click", async () => {
      setNetworkAndMaskInputs(sub.network_address, sub.netmask);
      await updateSubnetPreview();
      await loadIpamData();
    });
    elSavedSubnetsList.appendChild(btn);
  });
}

// 2. Calculateur de sous-réseau en temps réel
let calcDebounce = null;
async function updateSubnetPreview() {
  let netVal = elInputNetwork.value.trim();
  let maskVal = elInputMaskCustom.value.trim();

  if (netVal.includes("/")) {
    const parts = netVal.split("/");
    netVal = parts[0].trim();
    if (parts[1] && parts[1].trim()) {
      maskVal = "/" + parts[1].trim();
      elInputMaskCustom.value = maskVal;
    }
  }

  if (!netVal) return;

  try {
    const qs = new URLSearchParams({ network: netVal, mask: maskVal || "255.255.255.0" });
    const res = await fetch(`/api/subnet-calc?${qs.toString()}`);
    const data = await res.json();
    if (data.ok && data.subnet) {
      const s = data.subnet;
      state.subnetInfo = s;
      state.network = s.network_address;
      state.mask = s.netmask;

      elCalcCidr.textContent = s.cidr;
      elCalcNetAddr.textContent = s.network_address;
      elCalcNetmask.textContent = `${s.netmask} (/${s.prefixlen})`;
      elCalcRange.textContent = `${s.first_host} → ${s.last_host}`;
      elCalcBroadcast.textContent = s.broadcast_address;
      elCalcUsable.textContent = `${s.usable_hosts} hôtes utilisables`;

      const opt = Array.from(elSelectMaskPreset.options).find((o) => o.value === s.netmask);
      if (opt) {
        elSelectMaskPreset.value = s.netmask;
      }
    }
  } catch (_) {}
}

// 3. Chargement des données IPAM du sous-réseau sélectionné
async function loadIpamData() {
  const netVal = elInputNetwork.value.trim().split("/")[0].trim();
  const maskVal = elInputMaskCustom.value.trim() || "255.255.255.0";
  if (!netVal) return;

  try {
    const qs = new URLSearchParams({ network: netVal, mask: maskVal });
    const res = await fetch(`/api/ipam?${qs.toString()}`);
    const data = await res.json();
    if (!data.ok) {
      showToast(data.error || "Sous-réseau invalide", "error");
      return;
    }

    state.subnetInfo = data.subnet;
    state.addresses = data.addresses || [];
    state.stats = data.stats;
    state.lastScan = data.last_scan;

    renderKpis();
    renderSubnetGrid();
    renderIpamTable();
  } catch (err) {
    showToast("Erreur de chargement IPAM : " + err.message, "error");
  }
}

function renderKpis() {
  const st = state.stats;
  if (!st) return;

  elKpiOnlineCount.textContent = st.online_count;
  elKpiUtilizationPct.textContent = `${st.utilization_pct}% occupé`;
  elKpiUtilizationBar.style.width = `${Math.min(100, st.utilization_pct)}%`;

  elKpiDnsCount.textContent = st.dns_resolved_count;
  const dnsPct = st.online_count > 0 ? Math.round((st.dns_resolved_count / st.online_count) * 100) : 0;
  elKpiDnsRatio.textContent = `${dnsPct}% des IPs actives`;

  elKpiReservedCount.textContent = st.reserved_or_offline_count;
  elKpiFreeCount.textContent = st.free_count;
  elKpiTotalUsable.textContent = `sur ${st.usable_hosts} hôtes`;

  if (state.lastScan && state.lastScan.last_scan_at) {
    elKpiLastScanInfo.textContent = `Dernière maj : ${state.lastScan.last_scan_at}`;
  } else {
    elKpiLastScanInfo.textContent = `Aucun scan enregistré pour ${state.subnetInfo.cidr}`;
  }

  const usedList = state.addresses.filter((a) => a.is_online);
  const dnsList = state.addresses.filter((a) => Boolean(a.dns_name || a.custom_name));
  const knownList = state.addresses.filter(
    (a) => a.is_online || a.state === "reserved" || a.state === "offline"
  );
  const freeList = state.addresses.filter((a) => a.state === "free");

  elTabCountUsed.textContent = usedList.length;
  elTabCountDns.textContent = dnsList.length;
  elTabCountKnown.textContent = knownList.length;
  elTabCountFree.textContent = freeList.length;
  elTabCountAll.textContent = state.addresses.length;
}

// 4. Grille Visuelle du Sous-Réseau (Cartographie)
function renderSubnetGrid() {
  if (!state.subnetInfo) return;
  elGridSubnetTitle.textContent = `${state.subnetInfo.cidr} — Masque ${state.subnetInfo.netmask}`;
  elIpGridContainer.innerHTML = "";

  const fragment = document.createDocumentFragment();

  state.addresses.forEach((item) => {
    const cell = document.createElement("div");
    let cellClass = "ip-cell";

    if (item.state === "network") {
      cellClass += " cell-network";
    } else if (item.state === "broadcast") {
      cellClass += " cell-broadcast";
    } else if (item.is_local_server || item.is_gateway) {
      cellClass += " cell-special";
    } else if (item.is_online) {
      cellClass += " cell-active";
    } else if (item.state === "reserved" || item.state === "offline") {
      cellClass += " cell-reserved";
    }

    cell.className = cellClass;

    const hasDns = Boolean(item.dns_name || item.custom_name);
    const shortName = item.custom_name || item.dns_name || "";

    const tooltipParts = [`IP: ${item.ip}`];
    if (item.state === "network") tooltipParts.push("Statut: Adresse Réseau");
    else if (item.state === "broadcast") tooltipParts.push("Statut: Broadcast");
    else if (item.is_online) tooltipParts.push("Statut: EN LIGNE (Utilisée)");
    else if (item.state === "reserved") tooltipParts.push("Statut: RÉSERVÉE");
    else if (item.state === "offline") tooltipParts.push("Statut: HORS-LIGNE (Connue)");
    else tooltipParts.push("Statut: LIBRE");

    if (item.dns_name) tooltipParts.push(`Nom DNS: ${item.dns_name}`);
    if (item.custom_name) tooltipParts.push(`Alias: ${item.custom_name}`);
    if (item.mac_address) tooltipParts.push(`MAC: ${item.mac_address}`);
    if (item.vendor) tooltipParts.push(`Constructeur: ${item.vendor}`);
    if (item.latency_ms !== null && item.latency_ms !== undefined) {
      tooltipParts.push(`Ping: ${item.latency_ms} ms`);
    }
    if (item.open_ports && item.open_ports.length > 0) {
      tooltipParts.push(
        `Ports: ${item.open_ports.map((p) => p.port + "/" + p.service).join(", ")}`
      );
    }
    cell.title = tooltipParts.join("\n");

    const displayOctet =
      state.subnetInfo.prefixlen >= 24
        ? `.${item.last_octet}`
        : item.ip.split(".").slice(2).join(".");

    cell.innerHTML = `
      ${hasDns ? '<span class="dns-dot" title="Nom DNS résolu"></span>' : ""}
      <span>${escapeHtml(displayOctet)}</span>
      ${
        shortName
          ? `<span class="cell-sub">${escapeHtml(shortName.split(".")[0])}</span>`
          : ""
      }
    `;

    if (item.state !== "network" && item.state !== "broadcast") {
      cell.addEventListener("click", () => openIpModal(item));
    }
    fragment.appendChild(cell);
  });

  elIpGridContainer.appendChild(fragment);
}

// 5. Tableau IPAM Détaillé
function renderIpamTable() {
  const q = state.searchQuery.toLowerCase().trim();

  const filtered = state.addresses.filter((item) => {
    if (state.currentFilter === "used" && !item.is_online) return false;
    if (state.currentFilter === "dns" && !(item.dns_name || item.custom_name)) return false;
    if (
      state.currentFilter === "known" &&
      !(item.is_online || item.state === "reserved" || item.state === "offline")
    ) {
      return false;
    }
    if (state.currentFilter === "free" && item.state !== "free") return false;

    if (q) {
      const portsStr = (item.open_ports || [])
        .map((p) => `${p.port} ${p.service}`)
        .join(" ")
        .toLowerCase();
      const hay = [
        item.ip,
        item.dns_name,
        item.custom_name,
        item.mac_address,
        item.vendor,
        item.role,
        item.os_guess,
        item.notes,
        portsStr,
      ]
        .join(" ")
        .toLowerCase();
      if (!hay.includes(q)) return false;
    }

    return true;
  });

  elIpamTableBody.innerHTML = "";

  if (filtered.length === 0) {
    const tr = document.createElement("tr");
    const msg =
      state.currentFilter === "used" && (!state.stats || state.stats.online_count === 0)
        ? `Aucune adresse IPv4 en ligne pour <strong>${escapeHtml(
            state.subnetInfo ? state.subnetInfo.cidr : ""
          )}</strong>. Cliquez sur <strong>"Scanner ce Sous-Réseau Maintenant"</strong> ou sur <strong>"Ré-importer un Plan (CSV)"</strong>.`
        : "Aucune adresse IPv4 ne correspond aux critères de filtre ou de recherche.";
    tr.innerHTML = `<td colspan="8" class="empty-row">${msg}</td>`;
    elIpamTableBody.appendChild(tr);
    return;
  }

  const fragment = document.createDocumentFragment();

  filtered.forEach((item) => {
    const tr = document.createElement("tr");

    let statusBadgeHtml = "";
    if (item.state === "network" || item.state === "broadcast") {
      statusBadgeHtml = `<span class="status-pill status-free">${escapeHtml(item.role)}</span>`;
    } else if (item.is_local_server) {
      statusBadgeHtml = `<span class="status-pill status-special">● Serveur IPAM</span>`;
    } else if (item.is_gateway) {
      statusBadgeHtml = `<span class="status-pill status-special">● Passerelle</span>`;
    } else if (item.is_online) {
      statusBadgeHtml = `<span class="status-pill status-active">● En ligne (Utilisée)</span>`;
    } else if (item.state === "reserved") {
      statusBadgeHtml = `<span class="status-pill status-reserved">◆ Réservée</span>`;
    } else if (item.state === "offline") {
      statusBadgeHtml = `<span class="status-pill status-offline">○ Hors-ligne</span>`;
    } else {
      statusBadgeHtml = `<span class="status-pill status-free">Libre</span>`;
    }

    let dnsHtml = "";
    if (item.dns_name) {
      dnsHtml += `<span class="dns-primary mono">${escapeHtml(item.dns_name)}</span>`;
    }
    if (item.custom_name) {
      dnsHtml += `<span class="dns-custom">Alias: ${escapeHtml(item.custom_name)}</span>`;
    }
    if (!item.dns_name && !item.custom_name) {
      dnsHtml = `<span class="dns-empty">${item.is_online ? "Aucun PTR / DNS" : "—"}</span>`;
    }

    let macHtml = `<span class="dns-empty">—</span>`;
    if (item.mac_address || item.vendor) {
      macHtml = `
        ${item.mac_address ? `<span class="mac-line mono">${escapeHtml(item.mac_address)}</span>` : ""}
        ${item.vendor ? `<span class="vendor-line">${escapeHtml(item.vendor)}</span>` : ""}
      `;
    }

    let pingHtml = `<span class="dns-empty">—</span>`;
    if (item.latency_ms !== null && item.latency_ms !== undefined) {
      pingHtml = `
        <span class="mono text-success"><strong>${item.latency_ms} ms</strong></span>
        ${item.os_guess ? `<span class="vendor-line">${escapeHtml(item.os_guess)}</span>` : ""}
      `;
    } else if (item.detection_method) {
      pingHtml = `<span class="vendor-line">${escapeHtml(item.detection_method)}</span>`;
    }

    let portsHtml = `<span class="dns-empty">—</span>`;
    if (item.open_ports && item.open_ports.length > 0) {
      portsHtml = `<div class="ports-badges">${item.open_ports
        .map(
          (p) =>
            `<span class="port-badge" title="Port TCP ${p.port} ouvert">${p.port}/${escapeHtml(
              p.service
            )}</span>`
        )
        .join("")}</div>`;
    }

    const roleText = item.role && item.role !== "Disponible" ? item.role : "";
    const notesHtml = `
      ${roleText ? `<strong>${escapeHtml(roleText)}</strong>` : ""}
      ${item.notes ? `<div class="vendor-line">${escapeHtml(item.notes)}</div>` : ""}
      ${!roleText && !item.notes ? `<span class="dns-empty">—</span>` : ""}
    `;

    tr.innerHTML = `
      <td>
        <span class="ip-link mono">${escapeHtml(item.ip)}</span>
      </td>
      <td>${statusBadgeHtml}</td>
      <td>${dnsHtml}</td>
      <td>${macHtml}</td>
      <td>${pingHtml}</td>
      <td>${portsHtml}</td>
      <td>${notesHtml}</td>
      <td class="text-right">
        ${
          item.state !== "network" && item.state !== "broadcast"
            ? `<button type="button" class="btn btn-outline btn-sm btn-edit-ip">Détails / Éditer</button>`
            : ""
        }
      </td>
    `;

    if (item.state !== "network" && item.state !== "broadcast") {
      tr.querySelector(".ip-link").addEventListener("click", () => openIpModal(item));
      const editBtn = tr.querySelector(".btn-edit-ip");
      if (editBtn) {
        editBtn.addEventListener("click", () => openIpModal(item));
      }
    }

    fragment.appendChild(tr);
  });

  elIpamTableBody.appendChild(fragment);
}

// 6. Lancement du Scan Réseau & Suivi en Temps Réel
async function triggerNetworkScan(e) {
  if (e) e.preventDefault();
  if (state.isScanning) return;

  const netVal = elInputNetwork.value.trim().split("/")[0].trim();
  const maskVal = elInputMaskCustom.value.trim() || "255.255.255.0";
  const timeoutMs = parseInt(elSelectTimeout.value, 10) || 450;
  const resolveDns = elChkResolveDns.checked;
  const scanPorts = elChkScanPorts.checked;

  if (!netVal) {
    showToast("Veuillez saisir une adresse réseau ou IPv4 valide.", "error");
    return;
  }

  try {
    elBtnStartScan.disabled = true;
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        network: netVal,
        mask: maskVal,
        timeout_ms: timeoutMs,
        resolve_dns: resolveDns,
        scan_ports: scanPorts,
      }),
    });
    const data = await res.json();
    if (!data.ok) {
      elBtnStartScan.disabled = false;
      showToast(data.error || "Impossible de lancer le scan", "error");
      return;
    }

    showToast(`Scan démarré sur ${data.status.cidr}`, "info");
    startPollingScan();
  } catch (err) {
    elBtnStartScan.disabled = false;
    showToast("Erreur lors du démarrage du scan : " + err.message, "error");
  }
}

function startPollingScan() {
  state.isScanning = true;
  elBtnStartScan.disabled = true;
  elScanProgressPanel.classList.remove("hidden");

  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(checkScanStatus, 550);
  checkScanStatus();
}

async function checkScanStatus() {
  try {
    const res = await fetch("/api/scan/status");
    const st = await res.json();

    const total = st.total_ips || 1;
    const done = st.scanned_ips || 0;
    const pct = Math.min(100, Math.round((done / total) * 100));

    elProgressPhase.textContent = `${st.phase || "Scan en cours..."} (${st.cidr || ""})`;
    elProgressCounter.textContent = `${done} / ${st.total_ips || 0} IPs`;
    elProgressActiveFound.textContent = `${st.active_count || 0} actives`;
    elProgressDnsFound.textContent = `${st.dns_count || 0} DNS résolus`;
    elProgressElapsed.textContent = `${st.duration_sec || 0}s`;
    elProgressBarFill.style.width = `${pct}%`;

    if (!st.is_scanning) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
      state.isScanning = false;
      elBtnStartScan.disabled = false;

      if (st.error) {
        showToast("Erreur pendant le scan : " + st.error, "error");
      } else {
        showToast(
          `Scan terminé & archivé (${st.duration_sec}s) : ${st.active_count} IPs actives (${st.dns_count} DNS).`,
          "success"
        );
      }

      setTimeout(() => {
        elScanProgressPanel.classList.add("hidden");
      }, 2200);

      const ifaceRes = await fetch("/api/interfaces");
      const ifaceData = await ifaceRes.json();
      renderSavedSubnetsPills(ifaceData.saved_subnets || []);
      updateHistoryState(ifaceData.history || []);

      setActiveFilterTab("used");
      await loadIpamData();
    }
  } catch (_) {}
}

function setActiveFilterTab(filterName) {
  state.currentFilter = filterName;
  elFilterTabs.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.filter === filterName);
  });
}

// 7. Historique & Sauvegardes des Anciens Scans
function updateHistoryState(historyList) {
  state.history = historyList || [];
  elHeaderHistoryCount.textContent = state.history.length;
  renderHistoryTable();
}

function renderHistoryTable() {
  if (!elHistoryTableBody) return;
  elHistoryTableBody.innerHTML = "";

  if (!state.history.length) {
    elHistoryTableBody.innerHTML = `
      <tr>
        <td colspan="7" class="empty-row">Aucun scan ou sauvegarde dans l'historique.</td>
      </tr>
    `;
    return;
  }

  const fragment = document.createDocumentFragment();
  state.history.forEach((h) => {
    const tr = document.createElement("tr");
    let badgeType = `<span class="status-pill status-active">Scan Auto</span>`;
    if (h.source_type === "manual") {
      badgeType = `<span class="status-pill status-special">Sauvegarde</span>`;
    } else if (h.source_type === "import") {
      badgeType = `<span class="status-pill status-reserved">Import CSV</span>`;
    }

    tr.innerHTML = `
      <td class="mono">${escapeHtml(h.scanned_at)}</td>
      <td>
        <strong>${escapeHtml(h.title)}</strong>
        <div style="margin-top: 2px;">${badgeType}</div>
      </td>
      <td class="mono">
        <strong>${escapeHtml(h.cidr)}</strong>
        <span class="vendor-line">${escapeHtml(h.netmask)}</span>
      </td>
      <td class="mono text-success"><strong>${h.active_count || 0}</strong></td>
      <td class="mono text-accent"><strong>${h.dns_count || 0}</strong></td>
      <td class="mono">${h.reserved_count || 0}</td>
      <td class="text-right">
        <div class="actions-inline">
          <button type="button" class="btn btn-primary btn-sm btn-restore-hist">
            Charger dans l'éditeur
          </button>
          <button type="button" class="btn btn-danger-sm btn-sm btn-delete-hist" title="Supprimer cette sauvegarde">
            ✕
          </button>
        </div>
      </td>
    `;

    tr.querySelector(".btn-restore-hist").addEventListener("click", () => restoreHistorySnapshot(h.id));
    tr.querySelector(".btn-delete-hist").addEventListener("click", () => deleteHistorySnapshot(h.id));
    fragment.appendChild(tr);
  });

  elHistoryTableBody.appendChild(fragment);
}

async function openHistoryModal() {
  try {
    const res = await fetch("/api/history");
    const data = await res.json();
    if (data.ok) {
      updateHistoryState(data.history || []);
    }
  } catch (_) {}
  elHistoryModalBackdrop.classList.remove("hidden");
}

function closeHistoryModal() {
  elHistoryModalBackdrop.classList.add("hidden");
}

async function saveManualSnapshot(customTitle = "") {
  const netVal = elInputNetwork.value.trim().split("/")[0].trim();
  const maskVal = elInputMaskCustom.value.trim() || "255.255.255.0";
  const title =
    customTitle ||
    elInputSnapshotTitle.value.trim() ||
    `Sauvegarde ${state.subnetInfo ? state.subnetInfo.cidr : netVal}`;

  try {
    const res = await fetch("/api/history/save", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        network: netVal,
        mask: maskVal,
        title: title,
      }),
    });
    const data = await res.json();
    if (data.ok) {
      elInputSnapshotTitle.value = "";
      updateHistoryState(data.history || []);
      showToast(`Sauvegarde "${title}" enregistrée dans l'historique.`, "success");
    } else {
      showToast(data.error || "Erreur lors de la sauvegarde", "error");
    }
  } catch (err) {
    showToast("Erreur réseau : " + err.message, "error");
  }
}

async function restoreHistorySnapshot(historyId) {
  try {
    const res = await fetch("/api/history/restore", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: historyId }),
    });
    const data = await res.json();
    if (!data.ok) {
      showToast(data.error || "Erreur de restauration", "error");
      return;
    }

    const r = data.restored;
    setNetworkAndMaskInputs(r.network_address, r.netmask);
    await updateSubnetPreview();

    const ifaceRes = await fetch("/api/interfaces");
    const ifaceData = await ifaceRes.json();
    renderSavedSubnetsPills(ifaceData.saved_subnets || []);
    updateHistoryState(ifaceData.history || []);

    setActiveFilterTab("known");
    await loadIpamData();
    closeHistoryModal();
    showToast(
      `Scan "${r.title}" (${r.cidr}) restauré dans l'éditeur (${r.restored_records} IPs).`,
      "success"
    );
  } catch (err) {
    showToast("Erreur lors de la restauration : " + err.message, "error");
  }
}

async function deleteHistorySnapshot(historyId) {
  try {
    const res = await fetch("/api/history/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: historyId }),
    });
    const data = await res.json();
    if (data.ok) {
      updateHistoryState(data.history || []);
      showToast("Sauvegarde supprimée.", "info");
    }
  } catch (err) {
    showToast("Erreur : " + err.message, "error");
  }
}

// 8. Ré-importation d'un Plan Complet ou Partiel (CSV / JSON)
let pendingImportContent = "";
let pendingImportFilename = "";

function openImportModal() {
  pendingImportContent = "";
  pendingImportFilename = "";
  elInputImportFile.value = "";
  elImportFilePreview.classList.add("hidden");
  elImportFilePreview.innerHTML = "";
  elImportModalBackdrop.classList.remove("hidden");
}

function closeImportModal() {
  elImportModalBackdrop.classList.add("hidden");
}

function handleImportFileChange(e) {
  const file = e.target.files && e.target.files[0];
  if (!file) return;

  pendingImportFilename = file.name;
  const reader = new FileReader();
  reader.onload = (ev) => {
    pendingImportContent = String(ev.target.result || "");
    const lines = pendingImportContent.trim().splitlines
      ? pendingImportContent.trim().splitlines()
      : pendingImportContent.trim().split(/\r?\n/);

    elImportFilePreview.classList.remove("hidden");
    elImportFilePreview.innerHTML = `
      <strong>Fichier prêt :</strong> ${escapeHtml(file.name)} (${Math.max(0, lines.length - 1)} lignes détectées)<br/>
      <span class="text-muted">Les adresses IPv4, noms DNS, alias, adresses MAC et notes seront chargés et modifiables dans l'interface web.</span>
    `;
  };
  reader.readAsText(file, "utf-8");
}

async function submitImportPlan(e) {
  e.preventDefault();
  if (!pendingImportContent) {
    showToast("Veuillez sélectionner un fichier CSV à importer.", "error");
    return;
  }

  try {
    const res = await fetch("/api/import/plan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content: pendingImportContent,
        filename: pendingImportFilename,
        replace_subnet: elChkReplaceSubnet.checked,
      }),
    });
    const data = await res.json();
    if (!data.ok) {
      showToast(data.error || "Erreur lors de l'importation du plan", "error");
      return;
    }

    const imp = data.imported;
    setNetworkAndMaskInputs(imp.network_address, imp.netmask);
    await updateSubnetPreview();

    const ifaceRes = await fetch("/api/interfaces");
    const ifaceData = await ifaceRes.json();
    renderSavedSubnetsPills(ifaceData.saved_subnets || []);
    updateHistoryState(ifaceData.history || []);

    // Afficher l'onglet Utilisées + Réservées ou Tout le Sous-Réseau pour que l'utilisateur puisse tout modifier
    setActiveFilterTab(imp.imported_count > 0 ? "known" : "all");
    await loadIpamData();
    closeImportModal();
    showToast(
      `Plan "${pendingImportFilename}" importé sur ${imp.cidr} (${imp.imported_count} adresses actives/annotées sur ${imp.total_rows_read} lignes). Vous pouvez maintenant les modifier !`,
      "success"
    );
  } catch (err) {
    showToast("Erreur lors de l'importation : " + err.message, "error");
  }
}

// 9. Modal d'inspection et d'édition d'une IP
function openIpModal(item) {
  elModalIpTitle.textContent = item.ip;
  elEditIp.value = item.ip;

  if (item.is_online) {
    elModalStatusBadge.className = "status-pill status-active";
    elModalStatusBadge.textContent = "En ligne (Utilisée)";
  } else if (item.state === "reserved") {
    elModalStatusBadge.className = "status-pill status-reserved";
    elModalStatusBadge.textContent = "Réservée";
  } else if (item.state === "offline") {
    elModalStatusBadge.className = "status-pill status-offline";
    elModalStatusBadge.textContent = "Hors-ligne";
  } else {
    elModalStatusBadge.className = "status-pill status-free";
    elModalStatusBadge.textContent = "Libre";
  }

  elModalDnsVal.textContent = item.dns_name || "Non résolu";
  elModalMacVal.textContent = item.mac_address || "—";
  elModalVendorVal.textContent = item.vendor || "—";
  elModalPingVal.textContent =
    item.latency_ms !== null && item.latency_ms !== undefined
      ? `${item.latency_ms} ms ${item.ttl ? `(TTL ${item.ttl})` : ""}`
      : "—";
  elModalMethodVal.textContent = item.detection_method || "—";
  elModalLastSeenVal.textContent = item.last_seen || "Jamais vue";

  elModalPortsList.innerHTML = "";
  if (item.open_ports && item.open_ports.length > 0) {
    item.open_ports.forEach((p) => {
      const span = document.createElement("span");
      span.className = "port-badge";
      span.textContent = `${p.port} / ${p.service}`;
      elModalPortsList.appendChild(span);
    });
  } else {
    elModalPortsList.innerHTML = `<span class="text-muted">Aucun port TCP courant détecté ouvert</span>`;
  }

  elEditCustomName.value = item.custom_name || "";
  elEditDnsName.value = item.dns_name || "";
  elEditStatus.value =
    item.state === "free" ? "reserved" : item.status || (item.is_online ? "active" : "reserved");
  elEditRole.value = item.role && item.role !== "Disponible" ? item.role : "";
  elEditNotes.value = item.notes || "";

  elModalBackdrop.classList.remove("hidden");
}

function closeIpModal() {
  elModalBackdrop.classList.add("hidden");
}

async function saveIpModal(e) {
  e.preventDefault();
  const payload = {
    ip: elEditIp.value,
    subnet_cidr: state.subnetInfo ? state.subnetInfo.cidr : "",
    custom_name: elEditCustomName.value.trim(),
    dns_name: elEditDnsName.value.trim(),
    status: elEditStatus.value,
    role: elEditRole.value.trim(),
    notes: elEditNotes.value.trim(),
  };

  try {
    const res = await fetch("/api/ipam/update", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (data.ok) {
      showToast(`Adresse ${payload.ip} mise à jour dans l'IPAM`, "success");
      closeIpModal();
      await loadIpamData();
    } else {
      showToast(data.error || "Erreur lors de la sauvegarde", "error");
    }
  } catch (err) {
    showToast("Erreur réseau : " + err.message, "error");
  }
}

// 10. Événements UI
function bindEvents() {
  elSelectMaskPreset.addEventListener("change", () => {
    elInputMaskCustom.value = elSelectMaskPreset.value;
    updateSubnetPreview();
  });

  const onSubnetInput = () => {
    clearTimeout(calcDebounce);
    calcDebounce = setTimeout(updateSubnetPreview, 180);
  };
  elInputNetwork.addEventListener("input", onSubnetInput);
  elInputMaskCustom.addEventListener("input", onSubnetInput);

  elScanForm.addEventListener("submit", triggerNetworkScan);

  elBtnLoadSubnet.addEventListener("click", async () => {
    await updateSubnetPreview();
    await loadIpamData();
    showToast("Plan d'adressage chargé.", "info");
  });

  // Sauvegarde rapide de l'état courant
  elBtnQuickSaveSnapshot.addEventListener("click", () => {
    const cidr = state.subnetInfo ? state.subnetInfo.cidr : elInputNetwork.value.trim();
    saveManualSnapshot(`Sauvegarde manuelle ${cidr}`);
  });

  // Onglets de filtrage
  elFilterTabs.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      setActiveFilterTab(btn.dataset.filter);
      renderIpamTable();
    });
  });

  // Recherche instantanée
  elInputSearch.addEventListener("input", () => {
    state.searchQuery = elInputSearch.value;
    renderIpamTable();
  });

  // Génération PDF récapitulatif des IPs utilisées
  document.getElementById("btnExportPdf").addEventListener("click", () => {
    const netVal = elInputNetwork.value.trim().split("/")[0].trim();
    const maskVal = elInputMaskCustom.value.trim() || "255.255.255.0";
    const qs = new URLSearchParams({ network: netVal, mask: maskVal });
    showToast("Génération du rapport PDF des IPs utilisées...", "info");
    window.location.href = `/api/export/pdf?${qs.toString()}`;
  });

  // Export CSV
  document.getElementById("btnExportUsedCsv").addEventListener("click", () => {
    const netVal = elInputNetwork.value.trim().split("/")[0].trim();
    const maskVal = elInputMaskCustom.value.trim() || "255.255.255.0";
    const qs = new URLSearchParams({ network: netVal, mask: maskVal, only_used: "1" });
    window.location.href = `/api/export/csv?${qs.toString()}`;
  });

  document.getElementById("btnExportAllCsv").addEventListener("click", () => {
    const netVal = elInputNetwork.value.trim().split("/")[0].trim();
    const maskVal = elInputMaskCustom.value.trim() || "255.255.255.0";
    const qs = new URLSearchParams({ network: netVal, mask: maskVal, only_used: "0" });
    window.location.href = `/api/export/csv?${qs.toString()}`;
  });

  // Modal 1 : Édition IP
  document.getElementById("btnCloseModal").addEventListener("click", closeIpModal);
  document.getElementById("btnCancelModal").addEventListener("click", closeIpModal);
  elModalBackdrop.addEventListener("click", (e) => {
    if (e.target === elModalBackdrop) closeIpModal();
  });
  elModalEditForm.addEventListener("submit", saveIpModal);

  // Modal 2 : Historique & Sauvegardes
  document.getElementById("btnOpenHistoryModal").addEventListener("click", openHistoryModal);
  document.getElementById("btnCloseHistoryModal").addEventListener("click", closeHistoryModal);
  elHistoryModalBackdrop.addEventListener("click", (e) => {
    if (e.target === elHistoryModalBackdrop) closeHistoryModal();
  });
  elSaveSnapshotForm.addEventListener("submit", (e) => {
    e.preventDefault();
    saveManualSnapshot();
  });

  // Modal 3 : Import Plan CSV
  document.getElementById("btnOpenImportModal").addEventListener("click", openImportModal);
  document.getElementById("btnCloseImportModal").addEventListener("click", closeImportModal);
  document.getElementById("btnCancelImportModal").addEventListener("click", closeImportModal);
  elImportModalBackdrop.addEventListener("click", (e) => {
    if (e.target === elImportModalBackdrop) closeImportModal();
  });
  elInputImportFile.addEventListener("change", handleImportFileChange);
  elImportPlanForm.addEventListener("submit", submitImportPlan);

  // Modal 4 : Gestion Compte & Déconnexion
  const elAccountModal = document.getElementById("accountModalBackdrop");
  document.getElementById("btnOpenAccountModal").addEventListener("click", async () => {
    const res = await fetch("/api/auth/me");
    const data = await res.json();
    if (data.ok) {
      state.currentUser = data.username;
      state.users = data.users || [];
      document.getElementById("modalAccountUsername").textContent = data.username;
      renderUsersTable();
    }
    elAccountModal.classList.remove("hidden");
  });
  document.getElementById("btnCloseAccountModal").addEventListener("click", () => {
    elAccountModal.classList.add("hidden");
  });
  elAccountModal.addEventListener("click", (e) => {
    if (e.target === elAccountModal) elAccountModal.classList.add("hidden");
  });

  document.getElementById("changePasswordForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const curPwd = document.getElementById("inputCurrentPwd").value;
    const newPwd = document.getElementById("inputNewPwd").value;
    const res = await fetch("/api/auth/change-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ current_password: curPwd, new_password: newPwd }),
    });
    const data = await res.json();
    if (data.ok) {
      document.getElementById("inputCurrentPwd").value = "";
      document.getElementById("inputNewPwd").value = "";
      showToast("Mot de passe mis à jour avec succès !", "success");
    } else {
      showToast(data.error || "Erreur lors du changement de mot de passe", "error");
    }
  });

  document.getElementById("createUserForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const uName = document.getElementById("inputNewUsername").value.trim();
    const uPwd = document.getElementById("inputNewUserPwd").value;
    const res = await fetch("/api/auth/user/create", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: uName, password: uPwd }),
    });
    const data = await res.json();
    if (data.ok) {
      document.getElementById("inputNewUsername").value = "";
      document.getElementById("inputNewUserPwd").value = "";
      state.users = data.users || [];
      renderUsersTable();
      showToast(`Utilisateur "${uName}" créé avec succès.`, "success");
    } else {
      showToast(data.error || "Erreur de création", "error");
    }
  });

  document.getElementById("btnLogout").addEventListener("click", async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    window.location.href = "/login";
  });
}

function renderUsersTable() {
  const tbody = document.getElementById("usersTableBody");
  if (!tbody) return;
  tbody.innerHTML = "";
  (state.users || []).forEach((u) => {
    const tr = document.createElement("tr");
    const isSelf = u.username === state.currentUser;
    tr.innerHTML = `
      <td class="mono"><strong>${escapeHtml(u.username)}</strong> ${isSelf ? '<span class="status-pill status-active">Vous</span>' : ""}</td>
      <td>${escapeHtml(u.role || "admin")}</td>
      <td class="mono">${escapeHtml(u.created_at || "—")}</td>
      <td class="text-right">
        ${
          !isSelf
            ? `<button type="button" class="btn btn-danger-sm btn-sm btn-del-user">Supprimer</button>`
            : ""
        }
      </td>
    `;
    const delBtn = tr.querySelector(".btn-del-user");
    if (delBtn) {
      delBtn.addEventListener("click", async () => {
        const res = await fetch("/api/auth/user/delete", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: u.username }),
        });
        const data = await res.json();
        if (data.ok) {
          state.users = data.users || [];
          renderUsersTable();
          showToast(`Utilisateur "${u.username}" supprimé.`, "info");
        }
      });
    }
    tbody.appendChild(tr);
  });
}

document.addEventListener("DOMContentLoaded", initApp);
