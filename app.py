"""
Serveur Web IPAM (IP Address Management) & Scanner Réseau Local IPv4.
Supporte :
- Scan réseau multi-threadé + résolution DNS + ARP MAC + Ports TCP
- Sauvegarde automatique et manuelle de l'historique des scans (snapshots restaurables)
- Ré-importation de plans complets ou partiels (CSV / JSON) pour modification dans l'interface web
- Génération d'un rapport PDF récapitulatif des adresses IPv4 utilisées
"""

import csv
import io
import ipaddress
import json
import mimetypes
import os
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from oui_db import lookup_vendor, normalize_mac
from pdf_generator import generate_ipam_pdf
from scanner import (
    NetworkScannerManager,
    calculate_subnet_info,
    get_local_interfaces,
    parse_network_and_mask,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
DATA_DIR = os.environ.get("IPAM_DATA_DIR", BASE_DIR)
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.environ.get("IPAM_DB_PATH", os.path.join(DATA_DIR, "ipam.db"))

db_lock = threading.Lock()


def init_db():
    """Initialise la base de données SQLite pour l'IPAM et l'historique des scans."""
    with db_lock, sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS subnets (
                cidr TEXT PRIMARY KEY,
                network_address TEXT,
                netmask TEXT,
                prefixlen INTEGER,
                broadcast_address TEXT,
                usable_hosts INTEGER,
                last_scan_at TEXT,
                last_active_count INTEGER DEFAULT 0,
                last_dns_count INTEGER DEFAULT 0,
                last_duration_sec REAL DEFAULT 0.0,
                description TEXT DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ip_records (
                ip TEXT PRIMARY KEY,
                ip_int INTEGER,
                subnet_cidr TEXT,
                dns_name TEXT DEFAULT '',
                custom_name TEXT DEFAULT '',
                mac_address TEXT DEFAULT '',
                vendor TEXT DEFAULT '',
                status TEXT DEFAULT 'active',
                is_online INTEGER DEFAULT 0,
                is_gateway INTEGER DEFAULT 0,
                is_local_server INTEGER DEFAULT 0,
                latency_ms REAL,
                ttl INTEGER,
                open_ports_json TEXT DEFAULT '[]',
                role TEXT DEFAULT '',
                os_guess TEXT DEFAULT '',
                detection_method TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                first_seen TEXT,
                last_seen TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT DEFAULT '',
                source_type TEXT DEFAULT 'scan',
                cidr TEXT,
                network_address TEXT,
                netmask TEXT,
                prefixlen INTEGER,
                scanned_at TEXT,
                active_count INTEGER DEFAULT 0,
                dns_count INTEGER DEFAULT 0,
                reserved_count INTEGER DEFAULT 0,
                duration_sec REAL DEFAULT 0.0,
                snapshot_json TEXT DEFAULT '[]'
            )
            """
        )
        conn.commit()


def _create_history_snapshot_in_tx(
    conn: sqlite3.Connection,
    net: ipaddress.IPv4Network,
    title: str,
    source_type: str = "scan",
    duration_sec: float = 0.0,
) -> int:
    """Crée une entrée dans `scan_history` avec l'état complet des IPs du sous-réseau."""
    start_int = int(net.network_address)
    end_int = int(net.broadcast_address)
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM ip_records WHERE ip_int BETWEEN ? AND ? ORDER BY ip_int ASC",
        (start_int, end_int),
    ).fetchall()

    records_list = [dict(r) for r in rows]
    active_count = sum(1 for r in records_list if r.get("is_online"))
    dns_count = sum(1 for r in records_list if r.get("dns_name") or r.get("custom_name"))
    reserved_count = sum(
        1 for r in records_list if not r.get("is_online") and r.get("status") in ("reserved", "offline")
    )

    cur = conn.execute(
        """
        INSERT INTO scan_history (
            title, source_type, cidr, network_address, netmask, prefixlen,
            scanned_at, active_count, dns_count, reserved_count, duration_sec, snapshot_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            title or f"Scan {net}",
            source_type,
            str(net),
            str(net.network_address),
            str(net.netmask),
            net.prefixlen,
            now_str,
            active_count,
            dns_count,
            reserved_count,
            duration_sec,
            json.dumps(records_list, ensure_ascii=False),
        ),
    )
    return cur.lastrowid


def save_scan_results(net: ipaddress.IPv4Network, enriched_hosts: dict, duration_sec: float):
    """Enregistre les résultats d'un scan réseau dans la base SQLite et archive le scan dans l'historique."""
    cidr = str(net)
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    start_int = int(net.network_address)
    end_int = int(net.broadcast_address)

    dns_count = sum(1 for h in enriched_hosts.values() if h.get("dns_name"))

    with db_lock, sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        usable = max(0, net.num_addresses - 2) if net.prefixlen <= 30 else net.num_addresses
        conn.execute(
            """
            INSERT INTO subnets (
                cidr, network_address, netmask, prefixlen, broadcast_address,
                usable_hosts, last_scan_at, last_active_count, last_dns_count, last_duration_sec
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cidr) DO UPDATE SET
                last_scan_at = excluded.last_scan_at,
                last_active_count = excluded.last_active_count,
                last_dns_count = excluded.last_dns_count,
                last_duration_sec = excluded.last_duration_sec
            """,
            (
                cidr,
                str(net.network_address),
                str(net.netmask),
                net.prefixlen,
                str(net.broadcast_address),
                usable,
                now_str,
                len(enriched_hosts),
                dns_count,
                duration_sec,
            ),
        )

        # Marquer les anciennes IPs de cette plage comme hors-ligne (en conservant les réservations et notes)
        conn.execute(
            """
            UPDATE ip_records
            SET is_online = 0,
                latency_ms = NULL,
                status = CASE WHEN status = 'reserved' THEN 'reserved' ELSE 'offline' END
            WHERE ip_int BETWEEN ? AND ?
            """,
            (start_int, end_int),
        )

        # Insérer ou mettre à jour chaque hôte actif découvert
        for ip_s, h in enriched_hosts.items():
            existing = conn.execute(
                "SELECT first_seen, dns_name, mac_address, vendor, custom_name, notes, status, role FROM ip_records WHERE ip = ?",
                (ip_s,),
            ).fetchone()

            first_seen = existing["first_seen"] if existing and existing["first_seen"] else now_str
            dns_val = h.get("dns_name") or (existing["dns_name"] if existing else "")
            mac_val = h.get("mac_address") or (existing["mac_address"] if existing else "")
            vendor_val = h.get("vendor") or (existing["vendor"] if existing else "")
            custom_name = existing["custom_name"] if existing else ""
            notes = existing["notes"] if existing else ""
            role_val = h.get("role") or (existing["role"] if existing else "Hôte Réseau")

            conn.execute(
                """
                INSERT INTO ip_records (
                    ip, ip_int, subnet_cidr, dns_name, custom_name, mac_address, vendor,
                    status, is_online, is_gateway, is_local_server, latency_ms, ttl,
                    open_ports_json, role, os_guess, detection_method, notes, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    subnet_cidr = excluded.subnet_cidr,
                    dns_name = excluded.dns_name,
                    mac_address = excluded.mac_address,
                    vendor = excluded.vendor,
                    status = CASE WHEN ip_records.status = 'reserved' THEN 'reserved' ELSE 'active' END,
                    is_online = 1,
                    is_gateway = excluded.is_gateway,
                    is_local_server = excluded.is_local_server,
                    latency_ms = excluded.latency_ms,
                    ttl = excluded.ttl,
                    open_ports_json = excluded.open_ports_json,
                    role = excluded.role,
                    os_guess = excluded.os_guess,
                    detection_method = excluded.detection_method,
                    last_seen = excluded.last_seen
                """,
                (
                    ip_s,
                    h["ip_int"],
                    cidr,
                    dns_val,
                    custom_name,
                    mac_val,
                    vendor_val,
                    1 if h.get("is_gateway") else 0,
                    1 if h.get("is_local_server") else 0,
                    h.get("latency_ms"),
                    h.get("ttl"),
                    json.dumps(h.get("open_ports", [])),
                    role_val,
                    h.get("os_guess", ""),
                    h.get("detection_method", ""),
                    notes,
                    first_seen,
                    now_str,
                ),
            )

        # Archiver automatiquement ce scan dans scan_history
        _create_history_snapshot_in_tx(
            conn,
            net=net,
            title=f"Scan automatique {cidr}",
            source_type="scan",
            duration_sec=duration_sec,
        )
        conn.commit()


def get_history_list(limit: int = 50) -> list:
    """Retourne la liste des sauvegardes / anciens scans enregistrés."""
    with db_lock, sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, title, source_type, cidr, network_address, netmask, prefixlen,
                   scanned_at, active_count, dns_count, reserved_count, duration_sec
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def restore_history_snapshot(history_id: int) -> dict:
    """Restaure un ancien scan ou une sauvegarde dans le plan IPAM actif."""
    with db_lock, sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM scan_history WHERE id = ?", (history_id,)).fetchone()
        if not row:
            raise ValueError(f"Sauvegarde #{history_id} introuvable.")

        hist = dict(row)
        net = parse_network_and_mask(hist["network_address"], hist["netmask"])
        start_int = int(net.network_address)
        end_int = int(net.broadcast_address)

        records = json.loads(hist.get("snapshot_json") or "[]")

        # Purger les enregistrements actuels de cette plage avant restauration
        conn.execute(
            "DELETE FROM ip_records WHERE ip_int BETWEEN ? AND ?",
            (start_int, end_int),
        )

        for r in records:
            conn.execute(
                """
                INSERT INTO ip_records (
                    ip, ip_int, subnet_cidr, dns_name, custom_name, mac_address, vendor,
                    status, is_online, is_gateway, is_local_server, latency_ms, ttl,
                    open_ports_json, role, os_guess, detection_method, notes, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    r.get("ip"),
                    r.get("ip_int") or int(ipaddress.IPv4Address(r["ip"])),
                    r.get("subnet_cidr") or str(net),
                    r.get("dns_name", ""),
                    r.get("custom_name", ""),
                    r.get("mac_address", ""),
                    r.get("vendor", ""),
                    r.get("status", "active"),
                    int(bool(r.get("is_online"))),
                    int(bool(r.get("is_gateway"))),
                    int(bool(r.get("is_local_server"))),
                    r.get("latency_ms"),
                    r.get("ttl"),
                    r.get("open_ports_json") or json.dumps(r.get("open_ports", [])),
                    r.get("role", ""),
                    r.get("os_guess", ""),
                    r.get("detection_method", ""),
                    r.get("notes", ""),
                    r.get("first_seen", hist["scanned_at"]),
                    r.get("last_seen", hist["scanned_at"]),
                ),
            )

        usable = max(0, net.num_addresses - 2) if net.prefixlen <= 30 else net.num_addresses
        conn.execute(
            """
            INSERT INTO subnets (
                cidr, network_address, netmask, prefixlen, broadcast_address,
                usable_hosts, last_scan_at, last_active_count, last_dns_count, last_duration_sec
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cidr) DO UPDATE SET
                last_scan_at = excluded.last_scan_at,
                last_active_count = excluded.last_active_count,
                last_dns_count = excluded.last_dns_count,
                last_duration_sec = excluded.last_duration_sec
            """,
            (
                str(net),
                str(net.network_address),
                str(net.netmask),
                net.prefixlen,
                str(net.broadcast_address),
                usable,
                hist["scanned_at"],
                hist["active_count"],
                hist["dns_count"],
                hist["duration_sec"],
            ),
        )
        conn.commit()
        return {
            "id": hist["id"],
            "title": hist["title"],
            "cidr": str(net),
            "network_address": str(net.network_address),
            "netmask": str(net.netmask),
            "restored_records": len(records),
        }


def _parse_ports_string(ports_str: str) -> list:
    """Convertit une chaîne '80/HTTP, 443/HTTPS' en [{'port': 80, 'service': 'HTTP'}, ...]."""
    if not ports_str or not ports_str.strip():
        return []
    result = []
    for part in ports_str.split(","):
        p = part.strip()
        if not p:
            continue
        if "/" in p:
            port_s, svc = p.split("/", 1)
            if port_s.strip().isdigit():
                result.append({"port": int(port_s.strip()), "service": svc.strip()})
        elif p.isdigit():
            result.append({"port": int(p), "service": f"TCP/{p}"})
    return result


def import_plan_from_content(
    content_str: str,
    filename: str = "plan_importe.csv",
    override_network: str = "",
    override_mask: str = "",
    replace_subnet: bool = True,
) -> dict:
    """
    Importe un plan complet ou partiel précédemment exporté (CSV ou JSON) dans la base SQLite
    afin de pouvoir le visualiser et le modifier via l'application web.
    """
    text = content_str.lstrip("\ufeff").strip()
    if not text:
        raise ValueError("Le fichier importé est vide.")

    parsed_rows = []

    # 1. Support d'un fichier JSON éventuel
    if text.startswith("{") or text.startswith("["):
        data = json.loads(text)
        items = data.get("addresses", data) if isinstance(data, dict) else data
        for it in items:
            if isinstance(it, dict) and it.get("ip"):
                parsed_rows.append(it)
    else:
        # 2. Fichier CSV (détection automatique du délimiteur ';' ou ',')
        first_line = text.splitlines()[0]
        delimiter = ";" if first_line.count(";") >= first_line.count(",") else ","
        reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)

        for row in reader:
            # Normaliser les clés d'en-tête
            norm = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            ip_val = (
                norm.get("adresse ipv4")
                or norm.get("ip")
                or norm.get("ipv4")
                or norm.get("address")
                or ""
            )
            if not ip_val:
                continue

            raw_state = (norm.get("statut") or norm.get("state") or norm.get("status") or "").lower()
            raw_online = (norm.get("en ligne") or norm.get("online") or "").upper()
            dns_val = (
                norm.get("nom dns (ptr / hostname)")
                or norm.get("nom dns")
                or norm.get("dns_name")
                or norm.get("dns")
                or norm.get("hostname")
                or ""
            )
            custom_val = (
                norm.get("nom personnalisé")
                or norm.get("nom personnalise")
                or norm.get("alias")
                or norm.get("custom_name")
                or ""
            )
            mac_val = normalize_mac(norm.get("adresse mac") or norm.get("mac") or norm.get("mac_address") or "")
            vendor_val = (
                norm.get("constructeur (vendor)")
                or norm.get("constructeur")
                or norm.get("vendor")
                or (lookup_vendor(mac_val) if mac_val else "")
            )
            role_val = norm.get("rôle / type") or norm.get("role") or norm.get("type") or ""
            os_val = norm.get("os estimé") or norm.get("os estime") or norm.get("os") or ""
            lat_raw = norm.get("latence (ms)") or norm.get("latence") or norm.get("ping") or ""
            ports_raw = norm.get("ports ouverts") or norm.get("ports") or ""
            method_val = norm.get("méthode de détection") or norm.get("methode de detection") or "Import CSV"
            last_seen_val = norm.get("dernière détection") or norm.get("derniere detection") or ""
            notes_val = norm.get("notes") or norm.get("commentaires") or ""

            is_online = raw_online in ("OUI", "YES", "TRUE", "1") or raw_state in ("active", "en ligne", "utilisée", "utilisee")
            if raw_state in ("network", "broadcast", "adresse réseau"):
                state_norm = raw_state
            elif raw_state in ("reserved", "réservée", "reservee", "statique"):
                state_norm = "reserved"
            elif raw_state in ("offline", "hors-ligne", "hors ligne"):
                state_norm = "offline"
            elif is_online:
                state_norm = "active"
            else:
                state_norm = "free"

            latency_ms = None
            if lat_raw:
                try:
                    latency_ms = float(lat_raw.replace("ms", "").replace(",", ".").strip())
                except ValueError:
                    pass

            parsed_rows.append({
                "ip": ip_val,
                "state": state_norm,
                "status": "reserved" if state_norm == "reserved" else ("active" if is_online else "offline"),
                "is_online": is_online,
                "dns_name": dns_val,
                "custom_name": custom_val,
                "mac_address": mac_val,
                "vendor": vendor_val,
                "role": role_val,
                "os_guess": os_val,
                "latency_ms": latency_ms,
                "open_ports": _parse_ports_string(ports_raw),
                "detection_method": method_val,
                "last_seen": last_seen_val,
                "notes": notes_val,
            })

    if not parsed_rows:
        raise ValueError("Aucune ligne d'adresse IPv4 valide n'a été trouvée dans le fichier.")

    # Validation des IPs et détermination automatique du sous-réseau
    valid_ips = []
    for item in parsed_rows:
        try:
            ip_obj = ipaddress.IPv4Address(item["ip"])
            item["ip_int"] = int(ip_obj)
            valid_ips.append(ip_obj)
        except ValueError:
            continue

    if not valid_ips:
        raise ValueError("Aucune adresse IPv4 valide détectée.")

    if override_network and override_mask:
        net = parse_network_and_mask(override_network, override_mask)
    else:
        # Déduire le sous-réseau à partir de la plage d'IPs du fichier importé
        min_ip = min(valid_ips)
        max_ip = max(valid_ips)
        # Chercher le préfixe exact ou /24 par défaut
        inferred_net = ipaddress.IPv4Network(f"{min_ip}/24", strict=False)
        if max_ip not in inferred_net:
            for prefix in range(23, 15, -1):
                cand = ipaddress.IPv4Network(f"{min_ip}/{prefix}", strict=False)
                if max_ip in cand:
                    inferred_net = cand
                    break
        elif len(parsed_rows) in (128, 64, 32, 16, 8):
            # Si le plan complet exporté avait un masque plus petit (/25 à /29)
            prefix_map = {128: 25, 64: 26, 32: 27, 16: 28, 8: 29}
            cand = ipaddress.IPv4Network(f"{min_ip}/{prefix_map[len(parsed_rows)]}", strict=False)
            if max_ip in cand:
                inferred_net = cand
        net = inferred_net

    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    start_int = int(net.network_address)
    end_int = int(net.broadcast_address)

    imported_count = 0
    with db_lock, sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if replace_subnet:
            conn.execute(
                "DELETE FROM ip_records WHERE ip_int BETWEEN ? AND ?",
                (start_int, end_int),
            )

        for item in parsed_rows:
            if "ip_int" not in item:
                continue
            st = item.get("state", "free")
            has_custom_data = bool(
                item.get("dns_name")
                or item.get("custom_name")
                or item.get("mac_address")
                or item.get("notes")
                or (item.get("role") and item.get("role") not in ("Disponible", "Adresse Réseau", "Broadcast"))
            )
            # On ignore les lignes purement libres sans annotation ni statut actif/réservé
            if st in ("network", "broadcast"):
                continue
            if st == "free" and not item.get("is_online") and not has_custom_data:
                continue

            status_db = "reserved" if (st == "reserved" or (not item.get("is_online") and has_custom_data and st == "free")) else (
                "active" if item.get("is_online") else "offline"
            )
            role_val = item.get("role", "")
            if role_val == "Disponible":
                role_val = "Hôte Réseau" if item.get("is_online") else "Réservé"

            conn.execute(
                """
                INSERT INTO ip_records (
                    ip, ip_int, subnet_cidr, dns_name, custom_name, mac_address, vendor,
                    status, is_online, is_gateway, is_local_server, latency_ms, ttl,
                    open_ports_json, role, os_guess, detection_method, notes, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    subnet_cidr = excluded.subnet_cidr,
                    dns_name = excluded.dns_name,
                    custom_name = excluded.custom_name,
                    mac_address = excluded.mac_address,
                    vendor = excluded.vendor,
                    status = excluded.status,
                    is_online = excluded.is_online,
                    latency_ms = excluded.latency_ms,
                    open_ports_json = excluded.open_ports_json,
                    role = excluded.role,
                    os_guess = excluded.os_guess,
                    detection_method = excluded.detection_method,
                    notes = excluded.notes,
                    last_seen = excluded.last_seen
                """,
                (
                    item["ip"],
                    item["ip_int"],
                    str(net),
                    item.get("dns_name", ""),
                    item.get("custom_name", ""),
                    item.get("mac_address", ""),
                    item.get("vendor", ""),
                    status_db,
                    1 if item.get("is_online") else 0,
                    1 if "passerelle" in role_val.lower() else 0,
                    1 if "serveur ipam" in role_val.lower() else 0,
                    item.get("latency_ms"),
                    json.dumps(item.get("open_ports", [])),
                    role_val,
                    item.get("os_guess", ""),
                    item.get("detection_method") or "Import Plan CSV",
                    item.get("notes", ""),
                    item.get("last_seen") or now_str,
                    item.get("last_seen") or now_str,
                ),
            )
            imported_count += 1

        # Mettre à jour les compteurs du sous-réseau
        rows_after = conn.execute(
            "SELECT is_online, dns_name, custom_name FROM ip_records WHERE ip_int BETWEEN ? AND ?",
            (start_int, end_int),
        ).fetchall()
        online_c = sum(1 for r in rows_after if r["is_online"])
        dns_c = sum(1 for r in rows_after if r["dns_name"] or r["custom_name"])
        usable = max(0, net.num_addresses - 2) if net.prefixlen <= 30 else net.num_addresses

        conn.execute(
            """
            INSERT INTO subnets (
                cidr, network_address, netmask, prefixlen, broadcast_address,
                usable_hosts, last_scan_at, last_active_count, last_dns_count, last_duration_sec
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0.0)
            ON CONFLICT(cidr) DO UPDATE SET
                last_scan_at = excluded.last_scan_at,
                last_active_count = excluded.last_active_count,
                last_dns_count = excluded.last_dns_count
            """,
            (
                str(net),
                str(net.network_address),
                str(net.netmask),
                net.prefixlen,
                str(net.broadcast_address),
                usable,
                now_str,
                online_c,
                dns_c,
            ),
        )

        # Créer une entrée de sauvegarde dans l'historique
        history_id = _create_history_snapshot_in_tx(
            conn,
            net=net,
            title=f"Import : {filename}",
            source_type="import",
            duration_sec=0.0,
        )
        conn.commit()

    return {
        "cidr": str(net),
        "network_address": str(net.network_address),
        "netmask": str(net.netmask),
        "imported_count": imported_count,
        "total_rows_read": len(parsed_rows),
        "history_id": history_id,
    }


def get_subnet_ipam_data(network_ip: str, mask_str: str) -> dict:
    """
    Construit la vue complète IPAM pour le sous-réseau demandé.
    """
    subnet_info = calculate_subnet_info(network_ip, mask_str)
    net = parse_network_and_mask(network_ip, mask_str)
    start_int = int(net.network_address)
    end_int = int(net.broadcast_address)

    with db_lock, sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        subnet_row = conn.execute(
            "SELECT * FROM subnets WHERE cidr = ?", (str(net),)
        ).fetchone()

        rows = conn.execute(
            "SELECT * FROM ip_records WHERE ip_int BETWEEN ? AND ? ORDER BY ip_int ASC",
            (start_int, end_int),
        ).fetchall()

    records_by_ip = {}
    for r in rows:
        d = dict(r)
        try:
            d["open_ports"] = json.loads(d.get("open_ports_json") or "[]")
        except Exception:
            d["open_ports"] = []
        d["is_online"] = bool(d.get("is_online"))
        d["is_gateway"] = bool(d.get("is_gateway"))
        d["is_local_server"] = bool(d.get("is_local_server"))
        records_by_ip[d["ip"]] = d

    full_addresses = []
    online_count = 0
    reserved_or_offline_count = 0
    dns_resolved_count = 0

    max_grid_ips = 1024
    if net.num_addresses <= max_grid_ips:
        for ip_obj in net:
            ip_s = str(ip_obj)
            is_net_addr = (net.prefixlen <= 30) and (ip_obj == net.network_address)
            is_bcast_addr = (net.prefixlen <= 30) and (ip_obj == net.broadcast_address)

            rec = records_by_ip.get(ip_s)
            if is_net_addr:
                full_addresses.append({
                    "ip": ip_s,
                    "last_octet": ip_s.split(".")[-1],
                    "state": "network",
                    "label": "Adresse Réseau",
                    "dns_name": "",
                    "custom_name": "",
                    "mac_address": "",
                    "vendor": "",
                    "is_online": False,
                    "latency_ms": None,
                    "open_ports": [],
                    "role": "Adresse Réseau",
                    "notes": "",
                })
            elif is_bcast_addr:
                full_addresses.append({
                    "ip": ip_s,
                    "last_octet": ip_s.split(".")[-1],
                    "state": "broadcast",
                    "label": "Broadcast",
                    "dns_name": "",
                    "custom_name": "",
                    "mac_address": "",
                    "vendor": "",
                    "is_online": False,
                    "latency_ms": None,
                    "open_ports": [],
                    "role": "Broadcast",
                    "notes": "",
                })
            elif rec:
                if rec["is_online"]:
                    state = "active"
                    online_count += 1
                elif rec["status"] == "reserved":
                    state = "reserved"
                    reserved_or_offline_count += 1
                else:
                    state = "offline"
                    reserved_or_offline_count += 1

                if rec.get("dns_name") or rec.get("custom_name"):
                    if rec["is_online"]:
                        dns_resolved_count += 1

                full_addresses.append({
                    "ip": ip_s,
                    "last_octet": ip_s.split(".")[-1],
                    "state": state,
                    "status": rec.get("status", "active"),
                    "dns_name": rec.get("dns_name", ""),
                    "custom_name": rec.get("custom_name", ""),
                    "mac_address": rec.get("mac_address", ""),
                    "vendor": rec.get("vendor", ""),
                    "is_online": rec["is_online"],
                    "is_gateway": rec["is_gateway"],
                    "is_local_server": rec["is_local_server"],
                    "latency_ms": rec.get("latency_ms"),
                    "ttl": rec.get("ttl"),
                    "open_ports": rec.get("open_ports", []),
                    "role": rec.get("role", ""),
                    "os_guess": rec.get("os_guess", ""),
                    "detection_method": rec.get("detection_method", ""),
                    "notes": rec.get("notes", ""),
                    "first_seen": rec.get("first_seen", ""),
                    "last_seen": rec.get("last_seen", ""),
                })
            else:
                full_addresses.append({
                    "ip": ip_s,
                    "last_octet": ip_s.split(".")[-1],
                    "state": "free",
                    "status": "free",
                    "dns_name": "",
                    "custom_name": "",
                    "mac_address": "",
                    "vendor": "",
                    "is_online": False,
                    "is_gateway": False,
                    "is_local_server": False,
                    "latency_ms": None,
                    "ttl": None,
                    "open_ports": [],
                    "role": "Disponible",
                    "os_guess": "",
                    "detection_method": "",
                    "notes": "",
                    "first_seen": "",
                    "last_seen": "",
                })
    else:
        for ip_s, rec in records_by_ip.items():
            if rec["is_online"]:
                online_count += 1
                if rec.get("dns_name") or rec.get("custom_name"):
                    dns_resolved_count += 1
            else:
                reserved_or_offline_count += 1
            full_addresses.append({
                "ip": ip_s,
                "last_octet": ip_s.split(".")[-1],
                "state": "active" if rec["is_online"] else rec.get("status", "offline"),
                **rec,
            })

    usable = subnet_info["usable_hosts"]
    free_count = max(0, usable - online_count - reserved_or_offline_count)
    utilization_pct = round(((online_count + reserved_or_offline_count) / usable) * 100, 1) if usable > 0 else 0.0

    return {
        "subnet": subnet_info,
        "last_scan": dict(subnet_row) if subnet_row else None,
        "stats": {
            "usable_hosts": usable,
            "total_addresses": subnet_info["total_addresses"],
            "online_count": online_count,
            "reserved_or_offline_count": reserved_or_offline_count,
            "free_count": free_count,
            "dns_resolved_count": dns_resolved_count,
            "utilization_pct": utilization_pct,
        },
        "addresses": full_addresses,
    }


scanner_manager = NetworkScannerManager(on_scan_complete=save_scan_results)


class IPAMRequestHandler(BaseHTTPRequestHandler):
    """Gestionnaire HTTP pour l'API IPAM et les fichiers statiques."""

    def log_message(self, format, *args):
        pass

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw) if raw else {}

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        try:
            if path == "/api/interfaces":
                interfaces = get_local_interfaces()
                with db_lock, sqlite3.connect(DB_PATH) as conn:
                    conn.row_factory = sqlite3.Row
                    saved_subnets = [
                        dict(r)
                        for r in conn.execute(
                            "SELECT * FROM subnets ORDER BY last_scan_at DESC"
                        ).fetchall()
                    ]
                self._send_json({
                    "interfaces": interfaces,
                    "saved_subnets": saved_subnets,
                    "history": get_history_list(limit=30),
                    "scan_status": scanner_manager.get_status(),
                })
                return

            if path == "/api/history":
                self._send_json({"ok": True, "history": get_history_list(limit=100)})
                return

            if path == "/api/subnet-calc":
                net_ip = query.get("network", ["192.168.1.0"])[0]
                mask = query.get("mask", ["255.255.255.0"])[0]
                info = calculate_subnet_info(net_ip, mask)
                self._send_json({"ok": True, "subnet": info})
                return

            if path == "/api/scan/status":
                self._send_json(scanner_manager.get_status())
                return

            if path == "/api/ipam":
                net_ip = query.get("network", ["192.168.1.0"])[0]
                mask = query.get("mask", ["255.255.255.0"])[0]
                data = get_subnet_ipam_data(net_ip, mask)
                self._send_json({"ok": True, **data})
                return

            if path == "/api/export/csv":
                net_ip = query.get("network", ["192.168.1.0"])[0]
                mask = query.get("mask", ["255.255.255.0"])[0]
                only_used = query.get("only_used", ["0"])[0] == "1"
                data = get_subnet_ipam_data(net_ip, mask)

                output = io.StringIO()
                output.write("\ufeff")  # BOM UTF-8 pour Excel
                writer = csv.writer(output, delimiter=";")
                writer.writerow([
                    "Adresse IPv4",
                    "Statut",
                    "En Ligne",
                    "Nom DNS (PTR / Hostname)",
                    "Nom Personnalisé",
                    "Adresse MAC",
                    "Constructeur (Vendor)",
                    "Rôle / Type",
                    "OS Estimé",
                    "Latence (ms)",
                    "Ports Ouverts",
                    "Méthode de détection",
                    "Dernière Détection",
                    "Notes",
                ])

                for item in data["addresses"]:
                    if only_used and item["state"] in ("free", "network", "broadcast"):
                        continue
                    ports_str = ", ".join(f"{p['port']}/{p['service']}" for p in item.get("open_ports", []))
                    writer.writerow([
                        item["ip"],
                        item["state"].upper(),
                        "OUI" if item.get("is_online") else "NON",
                        item.get("dns_name", ""),
                        item.get("custom_name", ""),
                        item.get("mac_address", ""),
                        item.get("vendor", ""),
                        item.get("role", ""),
                        item.get("os_guess", ""),
                        item.get("latency_ms") if item.get("latency_ms") is not None else "",
                        ports_str,
                        item.get("detection_method", ""),
                        item.get("last_seen", ""),
                        item.get("notes", ""),
                    ])

                csv_bytes = output.getvalue().encode("utf-8")
                safe_cidr = data["subnet"]["cidr"].replace("/", "_")
                prefix_name = "IPAM_Utilisees" if only_used else "IPAM_Plan_Complet"
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header(
                    "Content-Disposition",
                    f'attachment; filename="{prefix_name}_{safe_cidr}.csv"',
                )
                self.send_header("Content-Length", str(len(csv_bytes)))
                self.end_headers()
                self.wfile.write(csv_bytes)
                return

            if path == "/api/export/pdf":
                net_ip = query.get("network", ["192.168.1.0"])[0]
                mask = query.get("mask", ["255.255.255.0"])[0]
                data = get_subnet_ipam_data(net_ip, mask)
                pdf_bytes = generate_ipam_pdf(data)
                safe_cidr = data["subnet"]["cidr"].replace("/", "_")

                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header(
                    "Content-Disposition",
                    f'attachment; filename="Recap_IPAM_{safe_cidr}.pdf"',
                )
                self.send_header("Content-Length", str(len(pdf_bytes)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(pdf_bytes)
                return

            # Fichiers statiques
            if path == "/" or path == "":
                file_path = os.path.join(STATIC_DIR, "index.html")
            else:
                rel_path = path.lstrip("/").replace("/", os.sep)
                file_path = os.path.abspath(os.path.join(STATIC_DIR, rel_path))
                if not file_path.startswith(os.path.abspath(STATIC_DIR)):
                    self._send_json({"error": "Accès interdit"}, status=403)
                    return

            if os.path.isfile(file_path):
                ctype, _ = mimetypes.guess_type(file_path)
                if not ctype:
                    ctype = "application/octet-stream"
                if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
                    ctype += "; charset=utf-8"
                with open(file_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(content)
            else:
                self._send_json({"error": "Ressource introuvable"}, status=404)

        except ValueError as ve:
            self._send_json({"ok": False, "error": str(ve)}, status=400)
        except Exception as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=500)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            body = self._read_json_body()

            if path == "/api/scan":
                network_ip = body.get("network", "").strip()
                mask_str = body.get("mask", "255.255.255.0").strip()
                timeout_ms = int(body.get("timeout_ms", 450))
                scan_ports = bool(body.get("scan_ports", True))
                resolve_dns = bool(body.get("resolve_dns", True))

                if not network_ip:
                    self._send_json({"ok": False, "error": "Veuillez saisir une adresse réseau IPv4."}, status=400)
                    return

                status = scanner_manager.start_scan(
                    network_ip=network_ip,
                    mask_str=mask_str,
                    timeout_ms=timeout_ms,
                    scan_ports=scan_ports,
                    resolve_dns=resolve_dns,
                )
                self._send_json({"ok": True, "status": status})
                return

            if path == "/api/ipam/update":
                ip_str = body.get("ip", "").strip()
                subnet_cidr = body.get("subnet_cidr", "").strip()
                custom_name = body.get("custom_name", "").strip()
                dns_name = body.get("dns_name", "").strip()
                status_val = body.get("status", "reserved").strip()
                role_val = body.get("role", "").strip()
                notes_val = body.get("notes", "").strip()

                ip_obj = ipaddress.IPv4Address(ip_str)
                now_str = time.strftime("%Y-%m-%d %H:%M:%S")

                with db_lock, sqlite3.connect(DB_PATH) as conn:
                    if status_val == "free" and not custom_name and not notes_val:
                        conn.execute("DELETE FROM ip_records WHERE ip = ? AND is_online = 0", (ip_str,))
                    else:
                        conn.execute(
                            """
                            INSERT INTO ip_records (
                                ip, ip_int, subnet_cidr, dns_name, custom_name, status, role, notes, first_seen, last_seen
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(ip) DO UPDATE SET
                                custom_name = excluded.custom_name,
                                dns_name = CASE WHEN excluded.dns_name != '' THEN excluded.dns_name ELSE ip_records.dns_name END,
                                status = excluded.status,
                                role = excluded.role,
                                notes = excluded.notes
                            """,
                            (
                                ip_str,
                                int(ip_obj),
                                subnet_cidr,
                                dns_name,
                                custom_name,
                                status_val,
                                role_val,
                                notes_val,
                                now_str,
                                now_str,
                            ),
                        )
                    conn.commit()

                self._send_json({"ok": True, "ip": ip_str})
                return

            if path == "/api/history/save":
                network_ip = body.get("network", "192.168.1.0").strip()
                mask_str = body.get("mask", "255.255.255.0").strip()
                title = body.get("title", "").strip()
                net = parse_network_and_mask(network_ip, mask_str)

                with db_lock, sqlite3.connect(DB_PATH) as conn:
                    hist_id = _create_history_snapshot_in_tx(
                        conn,
                        net=net,
                        title=title or f"Sauvegarde manuelle {net}",
                        source_type="manual",
                        duration_sec=0.0,
                    )
                    conn.commit()

                self._send_json({
                    "ok": True,
                    "history_id": hist_id,
                    "history": get_history_list(limit=50),
                })
                return

            if path == "/api/history/restore":
                history_id = int(body.get("id", 0))
                restored = restore_history_snapshot(history_id)
                self._send_json({
                    "ok": True,
                    "restored": restored,
                    "history": get_history_list(limit=50),
                })
                return

            if path == "/api/history/delete":
                history_id = int(body.get("id", 0))
                with db_lock, sqlite3.connect(DB_PATH) as conn:
                    conn.execute("DELETE FROM scan_history WHERE id = ?", (history_id,))
                    conn.commit()
                self._send_json({
                    "ok": True,
                    "history": get_history_list(limit=50),
                })
                return

            if path == "/api/import/plan":
                content_str = body.get("content", "")
                filename = body.get("filename", "plan_importe.csv")
                override_network = body.get("network", "").strip()
                override_mask = body.get("mask", "").strip()
                replace_subnet = bool(body.get("replace_subnet", True))

                result = import_plan_from_content(
                    content_str=content_str,
                    filename=filename,
                    override_network=override_network,
                    override_mask=override_mask,
                    replace_subnet=replace_subnet,
                )
                self._send_json({
                    "ok": True,
                    "imported": result,
                    "history": get_history_list(limit=50),
                })
                return

            self._send_json({"ok": False, "error": "Route POST inconnue"}, status=404)

        except ValueError as ve:
            self._send_json({"ok": False, "error": str(ve)}, status=400)
        except RuntimeError as re_err:
            self._send_json({"ok": False, "error": str(re_err)}, status=409)
        except Exception as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=500)


def run_server(host: str = "0.0.0.0", port: int = 8080):
    init_db()
    server = ThreadingHTTPServer((host, port), IPAMRequestHandler)
    ifaces = get_local_interfaces()
    print("=" * 65)
    print("  IPAM & Scanner Réseau Local IPv4 - Serveur Web Démarré")
    print("=" * 65)
    print(f"  URL Locale       : http://localhost:{port}")
    for iface in ifaces:
        print(f"  Interface détectée: {iface['name']} -> {iface['ip']} ({iface['cidr']} / Masque {iface['netmask']})")
    print("=" * 65)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt du serveur IPAM.")
        server.server_close()


if __name__ == "__main__":
    port_arg = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", "8080"))
    run_server(port=port_arg)
