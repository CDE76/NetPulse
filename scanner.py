"""
Moteur de découverte réseau local et scanneur IPv4 multi-threadé pour l'application IPAM.
Supporte :
- Sélection manuelle du réseau / sous-réseau et du masque (CIDR ou décimal pointé)
- Détection des interfaces locales du serveur (Windows / Linux / macOS)
- Ping ICMP parallèle + mesure de latence (ms)
- Lecture de la table ARP (adresses MAC + détection des hôtes pare-feu)
- Résolution DNS inverse (PTR) + fallback LLMNR / NetBIOS / mDNS
- Scan des ports TCP courants (SSH, DNS, HTTP, HTTPS, SMB, RDP, etc.)
"""

import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess
import threading
import time
from typing import Dict, List, Optional, Tuple

from oui_db import lookup_vendor, normalize_mac

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    135: "RPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9100: "Printer",
}

DEFAULT_SCAN_PORTS = [22, 53, 80, 135, 443, 445, 3389, 8080, 9100]


def netmask_to_prefixlen(mask_str: str) -> int:
    """Convertit un masque (ex: '24', '/24', '255.255.255.0') en longueur de préfixe CIDR (0-32)."""
    cleaned = str(mask_str).strip().lstrip("/")
    if cleaned.isdigit():
        prefix = int(cleaned)
        if 0 <= prefix <= 32:
            return prefix
        raise ValueError(f"Préfixe CIDR invalide : /{prefix}")
    # Format décimal pointé ex: 255.255.255.0
    net = ipaddress.IPv4Network(f"0.0.0.0/{cleaned}", strict=False)
    return net.prefixlen


def parse_network_and_mask(network_ip: str, mask_str: str) -> ipaddress.IPv4Network:
    """Construit un objet IPv4Network à partir d'une IP/réseau et d'un masque."""
    ip_clean = network_ip.strip()
    if "/" in ip_clean:
        ip_part, embedded_mask = ip_clean.split("/", 1)
        ip_clean = ip_part.strip()
        if not mask_str:
            mask_str = embedded_mask.strip()
    prefixlen = netmask_to_prefixlen(mask_str or "24")
    return ipaddress.IPv4Network(f"{ip_clean}/{prefixlen}", strict=False)


def calculate_subnet_info(network_ip: str, mask_str: str) -> Dict:
    """Calcule les informations détaillées d'un sous-réseau IPv4."""
    net = parse_network_and_mask(network_ip, mask_str)
    total_addresses = net.num_addresses
    if net.prefixlen <= 30:
        usable_hosts = max(0, total_addresses - 2)
        first_host = str(net.network_address + 1)
        last_host = str(net.broadcast_address - 1)
    elif net.prefixlen == 31:
        usable_hosts = 2
        first_host = str(net.network_address)
        last_host = str(net.broadcast_address)
    else:
        usable_hosts = 1
        first_host = str(net.network_address)
        last_host = str(net.network_address)

    return {
        "cidr": str(net),
        "network_address": str(net.network_address),
        "broadcast_address": str(net.broadcast_address),
        "netmask": str(net.netmask),
        "hostmask": str(net.hostmask),
        "prefixlen": net.prefixlen,
        "total_addresses": total_addresses,
        "usable_hosts": usable_hosts,
        "first_host": first_host,
        "last_host": last_host,
        "is_private": net.is_private,
    }


def get_local_interfaces() -> List[Dict]:
    """Détecte rapidement les interfaces réseau IPv4 locales du serveur (< 100ms)."""
    interfaces = []
    system = platform.system().lower()

    if system == "windows":
        try:
            proc = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True,
                text=True,
                encoding="cp850",
                errors="replace",
                timeout=3,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            current_adapter = "Interface Locale"
            current_mac = ""
            current_ip = None
            current_mask = None
            current_gw = ""

            def _flush_adapter():
                nonlocal current_ip, current_mask
                if current_ip and current_mask:
                    if not current_ip.startswith("169.254.") and current_ip != "127.0.0.1":
                        try:
                            net = ipaddress.IPv4Network(f"{current_ip}/{current_mask}", strict=False)
                            net_24 = ipaddress.IPv4Network(f"{current_ip}/24", strict=False)
                            interfaces.append({
                                "name": current_adapter,
                                "ip": current_ip,
                                "netmask": str(net.netmask),
                                "prefixlen": net.prefixlen,
                                "network": str(net.network_address),
                                "subnet_24": str(net_24.network_address),
                                "cidr": str(net),
                                "mac": current_mac,
                                "gateway": current_gw,
                            })
                        except ValueError:
                            pass
                current_ip = None
                current_mask = None

            for line in proc.stdout.splitlines():
                line_s = line.strip()
                if not line_s:
                    continue
                if not line.startswith(" ") and line_s.endswith(":"):
                    _flush_adapter()
                    current_adapter = line_s.rstrip(":").strip()
                    current_mac = ""
                    current_gw = ""
                elif ("Adresse physique" in line_s or "Physical Address" in line_s) and ":" in line_s:
                    m = re.search(r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})", line_s)
                    if m:
                        current_mac = normalize_mac(m.group(1))
                elif "IPv4" in line_s:
                    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line_s)
                    if m:
                        current_ip = m.group(1)
                elif ("Masque" in line_s or "Subnet Mask" in line_s) and current_ip:
                    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line_s)
                    if m:
                        current_mask = m.group(1)
                elif "Passerelle" in line_s or "Default Gateway" in line_s:
                    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line_s)
                    if m:
                        current_gw = m.group(1)
            _flush_adapter()
        except Exception:
            pass
    else:
        # Linux / macOS / Docker Container
        default_gw = ""
        try:
            gw_proc = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=3)
            m_gw = re.search(r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)", gw_proc.stdout)
            if m_gw:
                default_gw = m_gw.group(1)
        except Exception:
            pass

        try:
            proc = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, timeout=4)
            for line in proc.stdout.splitlines():
                m = re.search(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
                if m:
                    iface, ip_str, prefix_str = m.group(1), m.group(2), m.group(3)
                    if ip_str != "127.0.0.1" and not ip_str.startswith("169.254."):
                        net = ipaddress.IPv4Network(f"{ip_str}/{prefix_str}", strict=False)
                        net_24 = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
                        mac_addr = ""
                        try:
                            iface_clean = iface.split("@")[0]
                            with open(f"/sys/class/net/{iface_clean}/address", "r") as f:
                                mac_addr = normalize_mac(f.read().strip())
                        except Exception:
                            pass
                        interfaces.append({
                            "name": iface,
                            "ip": ip_str,
                            "netmask": str(net.netmask),
                            "prefixlen": net.prefixlen,
                            "network": str(net.network_address),
                            "subnet_24": str(net_24.network_address),
                            "cidr": str(net),
                            "mac": mac_addr,
                            "gateway": default_gw if ipaddress.IPv4Address(default_gw) in net else "" if default_gw else "",
                        })
        except Exception:
            pass

    # Ultime fallback socket UDP
    if not interfaces:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            interfaces.append({
                "name": "Interface Principale",
                "ip": local_ip,
                "netmask": "255.255.255.0",
                "prefixlen": 24,
                "network": str(net.network_address),
                "cidr": str(net),
                "mac": "",
                "gateway": "",
            })
        except Exception:
            pass

    return interfaces


def get_arp_table() -> Dict[str, str]:
    """Lit la table ARP du système (Windows arp -a + Linux /proc/net/arp & ip neigh) et retourne {ip: mac}."""
    arp_map: Dict[str, str] = {}
    pattern = re.compile(
        r"(\d{1,3}(?:\.\d{1,3}){3})\s+.*?([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})"
    )

    if platform.system().lower() != "windows":
        try:
            with open("/proc/net/arp", "r", encoding="utf-8") as f:
                for line in f.read().splitlines()[1:]:
                    m = pattern.search(line)
                    if m:
                        ip_str, mac_raw = m.group(1), m.group(2)
                        mac = normalize_mac(mac_raw)
                        if mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                            arp_map[ip_str] = mac
        except Exception:
            pass

        try:
            proc_neigh = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=4)
            for line in proc_neigh.stdout.splitlines():
                m = pattern.search(line)
                if m:
                    ip_str, mac_raw = m.group(1), m.group(2)
                    mac = normalize_mac(mac_raw)
                    if mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                        arp_map[ip_str] = mac
        except Exception:
            pass

    try:
        proc = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            encoding="oem" if platform.system().lower() == "windows" else "utf-8",
            errors="replace",
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        for line in proc.stdout.splitlines():
            m = pattern.search(line)
            if m:
                ip_str, mac_raw = m.group(1), m.group(2)
                mac = normalize_mac(mac_raw)
                if mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                    arp_map[ip_str] = mac
    except Exception:
        pass
    return arp_map


def ping_host(ip_str: str, timeout_ms: int = 500) -> Tuple[bool, Optional[float], Optional[int]]:
    """
    Effectue un ping ICMP vers `ip_str`.
    Retourne (is_alive, latency_ms, ttl).
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip_str]
    else:
        timeout_sec = max(1, int((timeout_ms + 999) / 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip_str]

    try:
        t0 = time.perf_counter()
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="oem" if system == "windows" else "utf-8",
            errors="replace",
            timeout=max(2.0, timeout_ms / 1000.0 + 1.5),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 1)
        out = proc.stdout

        # Vérifie la présence d'un TTL (signe fiable d'une réponse ICMP Echo Reply sous Windows/Linux/FR/EN)
        ttl_match = re.search(r"TTL[=\s:]+(\d+)", out, re.IGNORECASE)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            # Extraction du temps en ms (ex: temps=3 ms, time=2.4 ms, temps<1ms, time<1ms)
            time_match = re.search(r"(?:temps|time|zeit)[=<]\s*([0-9]+(?:[.,][0-9]+)?)\s*ms", out, re.IGNORECASE)
            if time_match:
                lat = float(time_match.group(1).replace(",", "."))
            elif "<1" in out or "< 1" in out:
                lat = 0.5
            else:
                lat = elapsed_ms
            return True, lat, ttl
    except Exception:
        pass
    return False, None, None


def resolve_dns_name(ip_str: str, is_local_server: bool = False) -> str:
    """
    Résout le nom DNS (PTR / Hostname / NetBIOS / mDNS) d'une adresse IPv4.
    """
    if is_local_server:
        try:
            return socket.getfqdn() or socket.gethostname()
        except Exception:
            pass

    # 1. Résolution DNS inverse standard (PTR / cache DNS local / fichier hosts)
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_str)
        if hostname and hostname != ip_str:
            return hostname
    except Exception:
        pass

    # 2. Essai getfqdn
    try:
        fqdn = socket.getfqdn(ip_str)
        if fqdn and fqdn != ip_str and not fqdn.startswith("in-addr.arpa"):
            return fqdn
    except Exception:
        pass

    # 3. Fallback Windows ping -a (résout NetBIOS / LLMNR / mDNS rapidement)
    if platform.system().lower() == "windows":
        try:
            proc = subprocess.run(
                ["ping", "-a", "-n", "1", "-w", "150", ip_str],
                capture_output=True,
                text=True,
                encoding="oem",
                errors="replace",
                timeout=1.5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            # La première ligne contient souvent : "Envoi d'une requête 'ping' sur NOM-HOTE [192.168.1.X]..."
            # ou "Pinging HOSTNAME [192.168.1.X]..."
            first_lines = " ".join(proc.stdout.splitlines()[:3])
            m = re.search(r"(?:sur|Pinging)\s+([^\s\[\]]+)\s+\[" + re.escape(ip_str) + r"\]", first_lines, re.IGNORECASE)
            if m:
                candidate = m.group(1).strip()
                if candidate and candidate != ip_str:
                    return candidate
        except Exception:
            pass

    return ""


def scan_tcp_ports(ip_str: str, ports: List[int], timeout_sec: float = 0.22) -> List[Dict]:
    """Scanne une liste de ports TCP sur `ip_str` et retourne les ports ouverts."""
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout_sec)
                res = s.connect_ex((ip_str, port))
                if res == 0:
                    open_ports.append({
                        "port": port,
                        "service": COMMON_PORTS.get(port, f"TCP/{port}"),
                    })
        except Exception:
            pass
    return open_ports


def guess_os_and_role(ttl: Optional[int], open_ports: List[Dict], vendor: str, hostname: str, is_gateway: bool, is_server: bool) -> Tuple[str, str]:
    """Déduit le système d'exploitation probable et le rôle de l'équipement."""
    port_nums = {p["port"] for p in open_ports}
    hn_lower = (hostname or "").lower()
    v_lower = (vendor or "").lower()

    # Rôle
    if is_server:
        role = "Serveur IPAM (Hôte local)"
    elif is_gateway:
        role = "Passerelle / Routeur"
    elif 9100 in port_nums or "imprimante" in v_lower or "epson" in v_lower or "canon" in v_lower or "brother" in v_lower:
        role = "Imprimante Réseau"
    elif 53 in port_nums:
        role = "Serveur DNS / Routeur"
    elif 3389 in port_nums or (445 in port_nums and 135 in port_nums):
        role = "Poste / Serveur Windows"
    elif "synology" in v_lower or "qnap" in v_lower or "nas" in hn_lower:
        role = "Stockage NAS"
    elif "ubiquiti" in v_lower or "mikrotik" in v_lower or "cisco" in v_lower or "fortinet" in v_lower or "tp-link" in v_lower or "netgear" in v_lower:
        role = "Équipement Réseau"
    elif "vmware" in v_lower or "proxmox" in v_lower or "hyper-v" in v_lower or "qemu" in v_lower:
        role = "Machine Virtuelle"
    elif "espressif" in v_lower or "philips" in v_lower or "sonos" in v_lower:
        role = "Objet Connecté (IoT)"
    elif 22 in port_nums or 80 in port_nums or 443 in port_nums:
        role = "Serveur / Équipement Web"
    else:
        role = "Hôte Réseau"

    # OS via TTL et ports
    os_guess = ""
    if 3389 in port_nums or 135 in port_nums:
        os_guess = "Windows"
    elif ttl is not None:
        if 100 <= ttl <= 130:
            os_guess = "Windows (TTL ~128)"
        elif 45 <= ttl <= 65:
            os_guess = "Linux / macOS / Unix (TTL ~64)"
        elif ttl > 200:
            os_guess = "Équipement Réseau / Solaris (TTL ~255)"

    return role, os_guess


class NetworkScannerManager:
    """Gère les scans réseau en tâche de fond et expose la progression en temps réel."""

    def __init__(self, on_scan_complete=None):
        self._lock = threading.Lock()
        self.on_scan_complete = on_scan_complete
        self.state = {
            "is_scanning": False,
            "cidr": "",
            "network_address": "",
            "netmask": "",
            "prefixlen": 24,
            "total_ips": 0,
            "scanned_ips": 0,
            "active_count": 0,
            "dns_count": 0,
            "started_at": None,
            "finished_at": None,
            "duration_sec": 0.0,
            "phase": "idle",
            "error": None,
            "live_hosts": [],
        }

    def get_status(self) -> Dict:
        with self._lock:
            return dict(self.state)

    def start_scan(
        self,
        network_ip: str,
        mask_str: str,
        timeout_ms: int = 450,
        scan_ports: bool = True,
        resolve_dns: bool = True,
    ) -> Dict:
        with self._lock:
            if self.state["is_scanning"]:
                raise RuntimeError("Un scan réseau est déjà en cours.")

        net = parse_network_and_mask(network_ip, mask_str)
        if net.num_addresses > 4096:
            raise ValueError(
                f"Le sous-réseau {net} contient {net.num_addresses} adresses. "
                "Veuillez sélectionner un masque entre /20 (4096 IPs) et /32 pour un scan rapide."
            )

        # Liste des adresses hôtes à scanner
        if net.prefixlen <= 30:
            host_ips = [str(ip) for ip in net.hosts()]
        else:
            host_ips = [str(ip) for ip in net]

        with self._lock:
            self.state = {
                "is_scanning": True,
                "cidr": str(net),
                "network_address": str(net.network_address),
                "broadcast_address": str(net.broadcast_address),
                "netmask": str(net.netmask),
                "prefixlen": net.prefixlen,
                "total_ips": len(host_ips),
                "scanned_ips": 0,
                "active_count": 0,
                "dns_count": 0,
                "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "finished_at": None,
                "duration_sec": 0.0,
                "phase": "Scan ICMP (Ping) en cours...",
                "error": None,
                "live_hosts": [],
            }

        thread = threading.Thread(
            target=self._run_scan_worker,
            args=(net, host_ips, timeout_ms, scan_ports, resolve_dns),
            daemon=True,
        )
        thread.start()
        return self.get_status()

    def _run_scan_worker(
        self,
        net: ipaddress.IPv4Network,
        host_ips: List[str],
        timeout_ms: int,
        scan_ports: bool,
        resolve_dns: bool,
    ):
        t_start = time.perf_counter()
        try:
            # 1. Identifier les IPs et passerelles locales du serveur
            local_ifaces = get_local_interfaces()
            local_ips_map = {iface["ip"]: iface for iface in local_ifaces}
            gateways = {iface["gateway"] for iface in local_ifaces if iface.get("gateway")}

            # 2. Phase 1 : Ping parallèle de toutes les IPs du sous-réseau
            ping_results: Dict[str, Tuple[bool, Optional[float], Optional[int]]] = {}
            max_workers = min(96, max(16, len(host_ips)))

            def _ping_task(ip_s: str):
                if ip_s in local_ips_map:
                    return ip_s, True, 0.1, 128
                alive, lat, ttl = ping_host(ip_s, timeout_ms=timeout_ms)
                return ip_s, alive, lat, ttl

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(_ping_task, ip_s) for ip_s in host_ips]
                for fut in concurrent.futures.as_completed(futures):
                    ip_s, alive, lat, ttl = fut.result()
                    ping_results[ip_s] = (alive, lat, ttl)
                    with self._lock:
                        self.state["scanned_ips"] += 1
                        if alive:
                            self.state["active_count"] += 1
                        self.state["duration_sec"] = round(time.perf_counter() - t_start, 1)

            # 3. Phase 2 : Lecture de la table ARP (détecte aussi les machines qui bloquent le ping ICMP !)
            with self._lock:
                self.state["phase"] = "Lecture de la table ARP & détection MAC..."
            arp_map = get_arp_table()
            for lif_ip, lif in local_ips_map.items():
                if lif.get("mac"):
                    arp_map[lif_ip] = lif["mac"]

            # Toute IP présente dans la table ARP ou ayant répondu au ping est active !
            active_ips = [
                ip_s
                for ip_s in host_ips
                if ping_results.get(ip_s, (False, None, None))[0] or (ip_s in arp_map) or (ip_s in local_ips_map)
            ]

            with self._lock:
                self.state["active_count"] = len(active_ips)
                self.state["phase"] = f"Résolution DNS & scan des services ({len(active_ips)} hôtes actifs)..."

            # 4. Phase 3 : Enrichissement des hôtes actifs (DNS + Ports TCP + Vendor OUI)
            enriched_hosts: Dict[str, Dict] = {}

            def _enrich_host(ip_s: str) -> Dict:
                alive_ping, lat, ttl = ping_results.get(ip_s, (False, None, None))
                is_local = ip_s in local_ips_map
                is_gw = ip_s in gateways or (ip_s.endswith(".1") or ip_s.endswith(".254")) and ip_s in gateways
                mac = arp_map.get(ip_s, "")
                vendor = lookup_vendor(mac) if mac else ("Hôte Local (Ce Serveur)" if is_local else "")

                dns_name = ""
                if resolve_dns:
                    dns_name = resolve_dns_name(ip_s, is_local_server=is_local)

                open_ports = []
                if scan_ports:
                    open_ports = scan_tcp_ports(ip_s, DEFAULT_SCAN_PORTS, timeout_sec=0.22)

                role, os_guess = guess_os_and_role(
                    ttl=ttl,
                    open_ports=open_ports,
                    vendor=vendor,
                    hostname=dns_name,
                    is_gateway=(ip_s in gateways),
                    is_server=is_local,
                )

                return {
                    "ip": ip_s,
                    "ip_int": int(ipaddress.IPv4Address(ip_s)),
                    "status": "active",
                    "is_online": True,
                    "is_local_server": is_local,
                    "is_gateway": ip_s in gateways,
                    "dns_name": dns_name,
                    "mac_address": mac,
                    "vendor": vendor,
                    "latency_ms": lat,
                    "ttl": ttl,
                    "open_ports": open_ports,
                    "role": role,
                    "os_guess": os_guess,
                    "detection_method": "ICMP + ARP" if (alive_ping and mac) else ("ICMP Ping" if alive_ping else ("Serveur Local" if is_local else "Table ARP (Pare-feu ICMP)")),
                    "last_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
                }

            if active_ips:
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(48, len(active_ips))) as executor:
                    futures = [executor.submit(_enrich_host, ip_s) for ip_s in active_ips]
                    for fut in concurrent.futures.as_completed(futures):
                        host_data = fut.result()
                        enriched_hosts[host_data["ip"]] = host_data
                        with self._lock:
                            if host_data.get("dns_name"):
                                self.state["dns_count"] += 1
                            self.state["live_hosts"].append(host_data)
                            self.state["duration_sec"] = round(time.perf_counter() - t_start, 1)

            duration = round(time.perf_counter() - t_start, 2)
            with self._lock:
                self.state["is_scanning"] = False
                self.state["phase"] = "Terminé"
                self.state["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                self.state["duration_sec"] = duration

            if self.on_scan_complete:
                self.on_scan_complete(net, enriched_hosts, duration)

        except Exception as exc:
            with self._lock:
                self.state["is_scanning"] = False
                self.state["phase"] = "Erreur"
                self.state["error"] = str(exc)
                self.state["duration_sec"] = round(time.perf_counter() - t_start, 2)
