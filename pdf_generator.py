"""
Générateur PDF natif (PDF 1.4 A4 Paysage) sans dépendances externes.
Génère un rapport récapitulatif professionnel des adresses IPv4 utilisées,
avec en-tête, statistiques du sous-réseau et tableau détaillé (IP, Statut, Nom DNS, MAC/Constructeur, Latence, Ports, Notes).
"""

import time
from typing import Dict, List


def _pdf_escape(text: str) -> str:
    """Échappe une chaîne pour la syntaxe PDF et l'encode en WinAnsi (cp1252)."""
    if text is None:
        return ""
    s = str(text)
    # Remplacements typographiques courants
    s = (
        s.replace("—", "-")
        .replace("–", "-")
        .replace("→", "->")
        .replace("•", "*")
        .replace("●", "*")
        .replace("◆", "*")
        .replace("○", "o")
    )
    # Filtrer en cp1252 compatible
    encoded_chars = []
    for ch in s:
        try:
            b = ch.encode("cp1252")[0]
            if ch in ("(", ")", "\\"):
                encoded_chars.append("\\" + ch)
            elif 32 <= b <= 126:
                encoded_chars.append(ch)
            elif b >= 128:
                encoded_chars.append(f"\\{b:03o}")
            else:
                encoded_chars.append(" ")
        except UnicodeEncodeError:
            encoded_chars.append("?")
    return "".join(encoded_chars)


def _truncate(text: str, max_len: int) -> str:
    if not text:
        return ""
    s = str(text).strip()
    if len(s) <= max_len:
        return s
    return s[: max_len - 1] + "."


def generate_ipam_pdf(ipam_data: Dict) -> bytes:
    """
    Construit un fichier PDF A4 Paysage (842 x 595 pt) récapitulant les IPs utilisées du sous-réseau.
    """
    subnet = ipam_data.get("subnet", {})
    stats = ipam_data.get("stats", {})
    last_scan = ipam_data.get("last_scan") or {}
    all_addresses: List[Dict] = ipam_data.get("addresses", [])

    # Filtrer les adresses utilisées (en ligne) ou réservées/connues
    used_addresses = [
        a
        for a in all_addresses
        if a.get("is_online") or a.get("state") in ("active", "reserved", "offline")
    ]

    page_w = 842.0
    page_h = 595.0
    margin_x = 32.0

    # Pagination : 22 lignes sur la page 1 (qui contient le bloc KPI), 26 lignes sur les suivantes
    rows_first_page = 21
    rows_other_page = 26

    pages_rows: List[List[Dict]] = []
    if not used_addresses:
        pages_rows.append([])
    else:
        pages_rows.append(used_addresses[:rows_first_page])
        rem = used_addresses[rows_first_page:]
        while rem:
            pages_rows.append(rem[:rows_other_page])
            rem = rem[rows_other_page:]

    total_pages = len(pages_rows)
    now_str = time.strftime("%d/%m/%Y %H:%M:%S")

    # Définition des colonnes du tableau (Total largeur = 842 - 64 = 778 pt)
    columns = [
        {"title": "Adresse IPv4", "x": 32, "w": 88},
        {"title": "Statut", "x": 120, "w": 68},
        {"title": "Nom DNS / Hostname", "x": 188, "w": 150},
        {"title": "Alias / Rôle", "x": 338, "w": 105},
        {"title": "Adresse MAC & Constructeur", "x": 443, "w": 150},
        {"title": "Ping", "x": 593, "w": 42},
        {"title": "Ports TCP Ouverts", "x": 635, "w": 100},
        {"title": "Notes", "x": 735, "w": 75},
    ]

    page_streams: List[bytes] = []

    for page_idx, rows in enumerate(pages_rows):
        cmds: List[str] = []

        # 1. Bandeau d'en-tête sombre (#111827)
        cmds.append("0.067 0.094 0.153 rg")
        cmds.append(f"0 {page_h - 62:.1f} {page_w:.1f} 62 re f")

        # Ligne d'accent bleue sous l'en-tête (#3b82f6)
        cmds.append("0.231 0.510 0.965 rg")
        cmds.append(f"0 {page_h - 65:.1f} {page_w:.1f} 3 re f")

        # Titre dans le bandeau
        cmds.append("BT /F2 16 Tf 1 1 1 rg")
        cmds.append(f"{margin_x:.1f} {page_h - 28:.1f} Td")
        cmds.append(f"({_pdf_escape('NetPulse IPAM - Rapport Récapitulatif des Adresses IPv4 Utilisées')}) Tj ET")

        sub_header = (
            f"Sous-réseau : {subnet.get('cidr', '')}   |   "
            f"Masque : {subnet.get('netmask', '')}   |   "
            f"Plage : {subnet.get('first_host', '')} -> {subnet.get('last_host', '')}   |   "
            f"Généré le : {now_str}"
        )
        cmds.append("BT /F1 9.5 Tf 0.79 0.84 0.88 rg")
        cmds.append(f"{margin_x:.1f} {page_h - 46:.1f} Td")
        cmds.append(f"({_pdf_escape(sub_header)}) Tj ET")

        # Numéro de page en haut à droite
        page_label = f"Page {page_idx + 1} / {total_pages}"
        cmds.append("BT /F2 9.5 Tf 0.58 0.64 0.72 rg")
        cmds.append(f"{page_w - 95:.1f} {page_h - 28:.1f} Td")
        cmds.append(f"({_pdf_escape(page_label)}) Tj ET")

        y_cursor = page_h - 80.0

        # 2. Cartes de synthèse KPI sur la première page
        if page_idx == 0:
            kpis = [
                (
                    "IPv4 EN LIGNE (ACTIVES)",
                    f"{stats.get('online_count', 0)} IPs",
                    f"Occupation : {stats.get('utilization_pct', 0)}% ({stats.get('usable_hosts', 0)} hôtes)",
                    (0.063, 0.725, 0.506),
                ),
                (
                    "NOMS DNS RÉSOLUS",
                    f"{stats.get('dns_resolved_count', 0)} hôtes",
                    "Résolution PTR / Hostname / NetBIOS",
                    (0.024, 0.714, 0.831),
                ),
                (
                    "RÉSERVÉES / HORS-LIGNE",
                    f"{stats.get('reserved_or_offline_count', 0)} IPs",
                    "Adresses statiques ou connues",
                    (0.961, 0.620, 0.043),
                ),
                (
                    "ADRESSES IPv4 LIBRES",
                    f"{stats.get('free_count', 0)} IPs",
                    f"Dernier scan : {last_scan.get('last_scan_at') or 'Manuel/Import'}",
                    (0.392, 0.455, 0.545),
                ),
            ]
            card_w = (page_w - 2 * margin_x - 3 * 12.0) / 4.0
            card_h = 48.0
            card_y = y_cursor - card_h

            for i, (k_title, k_val, k_sub, rgb) in enumerate(kpis):
                cx = margin_x + i * (card_w + 12.0)
                # Fond gris très clair
                cmds.append("0.961 0.969 0.980 rg")
                cmds.append("0.82 0.86 0.91 RG 0.8 w")
                cmds.append(f"{cx:.1f} {card_y:.1f} {card_w:.1f} {card_h:.1f} re B")
                # Barre latérale colorée
                cmds.append(f"{rgb[0]:.3f} {rgb[1]:.3f} {rgb[2]:.3f} rg")
                cmds.append(f"{cx:.1f} {card_y:.1f} 4 {card_h:.1f} re f")

                cmds.append("BT /F2 7.5 Tf 0.39 0.45 0.55 rg")
                cmds.append(f"{cx + 10:.1f} {card_y + 35:.1f} Td ({_pdf_escape(k_title)}) Tj ET")

                cmds.append("BT /F2 13 Tf 0.07 0.09 0.15 rg")
                cmds.append(f"{cx + 10:.1f} {card_y + 19:.1f} Td ({_pdf_escape(k_val)}) Tj ET")

                cmds.append("BT /F1 7.5 Tf 0.39 0.45 0.55 rg")
                cmds.append(f"{cx + 10:.1f} {card_y + 7:.1f} Td ({_pdf_escape(_truncate(k_sub, 38))}) Tj ET")

            y_cursor = card_y - 16.0

        # 3. En-tête du tableau
        th_h = 20.0
        th_y = y_cursor - th_h
        cmds.append("0.118 0.161 0.231 rg")
        cmds.append(f"{margin_x:.1f} {th_y:.1f} {page_w - 2 * margin_x:.1f} {th_h:.1f} re f")

        for col in columns:
            cmds.append("BT /F2 8 Tf 0.95 0.96 0.98 rg")
            cmds.append(f"{col['x'] + 4:.1f} {th_y + 6:.1f} Td ({_pdf_escape(col['title'])}) Tj ET")

        y_cursor = th_y
        row_h = 18.5

        if not rows:
            cmds.append("0.97 0.98 0.99 rg")
            cmds.append(f"{margin_x:.1f} {y_cursor - 32:.1f} {page_w - 2 * margin_x:.1f} 32 re f")
            cmds.append("BT /F1 9.5 Tf 0.4 0.45 0.52 rg")
            cmds.append(
                f"{margin_x + 16:.1f} {y_cursor - 20:.1f} Td "
                f"({_pdf_escape('Aucune adresse IPv4 active ou réservée enregistrée sur ce sous-réseau.')}) Tj ET"
            )
        else:
            for r_idx, item in enumerate(rows):
                ry = y_cursor - row_h
                # Couleur de fond alternée
                if r_idx % 2 == 0:
                    cmds.append("1 1 1 rg")
                else:
                    cmds.append("0.965 0.973 0.986 rg")
                cmds.append(f"{margin_x:.1f} {ry:.1f} {page_w - 2 * margin_x:.1f} {row_h:.1f} re f")

                # Bordure inférieure de ligne
                cmds.append("0.88 0.91 0.94 RG 0.5 w")
                cmds.append(f"{margin_x:.1f} {ry:.1f} m {page_w - margin_x:.1f} {ry:.1f} l S")

                ip_txt = item.get("ip", "")
                if item.get("is_local_server"):
                    status_txt = "Serveur IPAM"
                    st_rgb = (0.45, 0.22, 0.85)
                elif item.get("is_gateway"):
                    status_txt = "Passerelle"
                    st_rgb = (0.45, 0.22, 0.85)
                elif item.get("is_online"):
                    status_txt = "En ligne"
                    st_rgb = (0.04, 0.55, 0.38)
                elif item.get("state") == "reserved":
                    status_txt = "Réservée"
                    st_rgb = (0.80, 0.45, 0.02)
                else:
                    status_txt = "Hors-ligne"
                    st_rgb = (0.45, 0.50, 0.58)

                dns_txt = item.get("dns_name") or "-"
                alias_role_parts = []
                if item.get("custom_name"):
                    alias_role_parts.append(item["custom_name"])
                if item.get("role") and item.get("role") not in ("Disponible", "Hôte Réseau"):
                    alias_role_parts.append(item["role"])
                alias_txt = " / ".join(alias_role_parts) if alias_role_parts else (item.get("role") or "-")

                mac_vendor_parts = []
                if item.get("mac_address"):
                    mac_vendor_parts.append(item["mac_address"])
                if item.get("vendor") and item.get("vendor") != "Constructeur inconnu":
                    mac_vendor_parts.append(item["vendor"])
                mac_txt = " - ".join(mac_vendor_parts) if mac_vendor_parts else "-"

                lat = item.get("latency_ms")
                ping_txt = f"{lat} ms" if lat is not None else "-"

                ports = item.get("open_ports") or []
                ports_txt = ", ".join(f"{p['port']}/{p['service']}" for p in ports) if ports else "-"
                notes_txt = item.get("notes") or "-"

                text_y = ry + 5.5

                # Col 0: IP ( Police Courier Gras )
                cmds.append("BT /F3 8.5 Tf 0.08 0.12 0.20 rg")
                cmds.append(f"{columns[0]['x'] + 4:.1f} {text_y:.1f} Td ({_pdf_escape(ip_txt)}) Tj ET")

                # Col 1: Statut (Coloré)
                cmds.append(f"BT /F2 8 Tf {st_rgb[0]:.2f} {st_rgb[1]:.2f} {st_rgb[2]:.2f} rg")
                cmds.append(f"{columns[1]['x'] + 4:.1f} {text_y:.1f} Td ({_pdf_escape(_truncate(status_txt, 14))}) Tj ET")

                # Col 2: DNS
                cmds.append("BT /F2 8 Tf 0.03 0.35 0.65 rg")
                cmds.append(f"{columns[2]['x'] + 4:.1f} {text_y:.1f} Td ({_pdf_escape(_truncate(dns_txt, 31))}) Tj ET")

                # Col 3: Alias / Rôle
                cmds.append("BT /F1 8 Tf 0.15 0.20 0.28 rg")
                cmds.append(f"{columns[3]['x'] + 4:.1f} {text_y:.1f} Td ({_pdf_escape(_truncate(alias_txt, 22))}) Tj ET")

                # Col 4: MAC & Vendor
                cmds.append("BT /F1 7.8 Tf 0.20 0.25 0.33 rg")
                cmds.append(f"{columns[4]['x'] + 4:.1f} {text_y:.1f} Td ({_pdf_escape(_truncate(mac_txt, 32))}) Tj ET")

                # Col 5: Ping
                cmds.append("BT /F1 8 Tf 0.15 0.20 0.28 rg")
                cmds.append(f"{columns[5]['x'] + 4:.1f} {text_y:.1f} Td ({_pdf_escape(_truncate(ping_txt, 9))}) Tj ET")

                # Col 6: Ports
                cmds.append("BT /F1 7.5 Tf 0.15 0.20 0.28 rg")
                cmds.append(f"{columns[6]['x'] + 4:.1f} {text_y:.1f} Td ({_pdf_escape(_truncate(ports_txt, 22))}) Tj ET")

                # Col 7: Notes
                cmds.append("BT /F1 7.5 Tf 0.35 0.40 0.48 rg")
                cmds.append(f"{columns[7]['x'] + 4:.1f} {text_y:.1f} Td ({_pdf_escape(_truncate(notes_txt, 16))}) Tj ET")

                y_cursor = ry

        # Pied de page
        cidr_label = subnet.get("cidr", "")
        footer_text = f"NetPulse IPAM - Récapitulatif IPv4 ({cidr_label}) - Total IPs listées dans ce rapport : {len(used_addresses)}"
        cmds.append("BT /F1 7.5 Tf 0.50 0.55 0.62 rg")
        cmds.append(
            f"{margin_x:.1f} 14.0 Td "
            f"({_pdf_escape(footer_text)}) Tj ET"
        )

        stream_str = "\n".join(cmds)
        page_streams.append(stream_str.encode("latin-1", errors="replace"))

    # Assemblage de la structure PDF 1.4
    # Objets :
    # 1: Catalog
    # 2: Pages
    # 3: Font F1 (Helvetica)
    # 4: Font F2 (Helvetica-Bold)
    # 5: Font F3 (Courier-Bold)
    # Pour chaque page i (0..N-1) :
    #   obj_page = 6 + 2*i
    #   obj_content = 6 + 2*i + 1
    objects: List[bytes] = []

    def add_obj(content: bytes) -> int:
        objects.append(content)
        return len(objects)

    add_obj(b"<< /Type /Catalog /Pages 2 0 R >>")  # 1
    add_obj(b"")  # 2 (rempli après création des pages)
    add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")  # 3
    add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")  # 4
    add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold /Encoding /WinAnsiEncoding >>")  # 5

    page_obj_ids = []
    for stream_bytes in page_streams:
        page_id = len(objects) + 1
        content_id = page_id + 1
        page_dict = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {page_w:.0f} {page_h:.0f}] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> "
            f"/Contents {content_id} 0 R >>"
        ).encode("ascii")
        add_obj(page_dict)
        content_obj = (
            f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii")
            + stream_bytes
            + b"\nendstream"
        )
        add_obj(content_obj)
        page_obj_ids.append(page_id)

    kids_str = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
    objects[1] = f"<< /Type /Pages /Kids [ {kids_str} ] /Count {len(page_obj_ids)} >>".encode("ascii")

    # Construction finale avec table xref
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for idx, obj_bytes in enumerate(objects, start=1):
        offsets.append(len(out))
        out.extend(f"{idx} 0 obj\n".encode("ascii"))
        out.extend(obj_bytes)
        out.extend(b"\nendobj\n")

    xref_pos = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("ascii"))

    out.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii")
    )
    return bytes(out)
