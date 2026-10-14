#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# +--------------------------------------------------------------------------+
# | export_userprofile                                                       |
# +--------------------------------------------------------------------------+
# | Copyright (c) 2004-2017 S.p.A. <info@endian.com>                         |
# |         Endian S.p.A.                                                    |
# |         via Pillhof 47                                                   |
# |         39057 Appiano (BZ)                                               |
# |         Italy                                                            |
# |                                                                          |
# | This program is free software; you can redistribute it and/or modify     |
# | it under the terms of the GNU General Public License as published by     |
# | the Free Software Foundation; either version 2 of the License, or        |
# | (at your option) any later version.                                      |
# |                                                                          |
# | This program is distributed in the hope that it will be useful,          |
# | but WITHOUT ANY WARRANTY; without even the implied warranty of           |
# | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            |
# | GNU General Public License for more details.                             |
# |                                                                          |
# | You should have received a copy of the GNU General Public License along  |
# | with this program; if not, write to the Free Software Foundation, Inc.,  |
# | 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.              |
# +--------------------------------------------------------------------------+
__author__ = "Luca Radaelli"

"""Export an Endian OpenVPN client profile without endian.job.commons.

Adapted from Endian S.p.A.'s export_userprofile (Luca Radaelli, 2017).
Original program: GPL v2 or later; this adaptation is distributed on the
same terms. Reads firewall configuration only; creates a local .ovpn file.

Requires Python >= 3.8 and PyYAML.
"""

import argparse
import os
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML non disponibile: verifica con 'python3 -c \"import yaml\"'.")

DEFAULTS = {
    "settings": "/var/efw/openvpn/settings",
    "servers": "/var/efw/openvpn/server",
    "users": "/var/efw/access/user",
    "ca_dir": "/var/efw/vpn/ca/cacerts",
    "cert_dir": "/var/efw/vpn/ca/certs",
}
AUTH_TYPES = {"psk", "cert", "psk_cert"}


def fail(message):
    raise RuntimeError(message)


def enabled(value):
    return value is True or str(value).strip().lower() in {"on", "yes", "true", "1"}


def read_settings(path):
    """Read Endian KEY=VALUE settings without executing shell content."""
    result = {}
    if not path.is_file():
        print(f"Avviso: impostazioni globali non trovate: {path}", file=sys.stderr)
        return result
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        result[key.strip()] = value
    return result


def read_yaml_entries(path):
    if not path.is_file():
        fail(f"File di configurazione non trovato: {path}")
    with path.open("r", encoding="utf-8") as stream:
        for doc in yaml.safe_load_all(stream):
            if not isinstance(doc, dict):
                continue
            for entry_id, data in doc.items():
                if isinstance(data, dict):
                    yield str(entry_id), data


def choose(label, options):
    """Select a 1-based index and return its associated value."""
    if len(options) == 1:
        print(f"{label}: {options[0][0]} (selezionato automaticamente)")
        return options[0][1]
    for n, (description, _) in enumerate(options, 1):
        print(f"  {n}) {description}")
    while True:
        try:
            choice = int(input(f"{label} [1-{len(options)}]: "))
            if 1 <= choice <= len(options):
                return options[choice - 1][1]
        except (ValueError, EOFError):
            pass
        print("Selezione non valida.")


def choose_server(path, requested_id):
    servers = [
        (sid, value)
        for sid, value in read_yaml_entries(path)
        if enabled(value.get("enabled", False))
    ]
    if not servers:
        fail("Nessuna istanza OpenVPN abilitata trovata.")
    if requested_id is not None:
        match = next(((sid, cfg) for sid, cfg in servers if sid == requested_id), None)
        if match is None:
            fail(f"Istanza '{requested_id}' inesistente o disabilitata.")
        return match
    print("Istanze OpenVPN abilitate:")
    return choose(
        "Scegli l'istanza",
        [
            (
                f"ID {sid} - {cfg.get('name', 'senza nome')} "
                f"({cfg.get('openvpn_protocol', '?')}/{cfg.get('openvpn_port', '?')}, "
                f"{cfg.get('device_type', '?')})",
                (sid, cfg),
            )
            for sid, cfg in servers
        ],
    )


def choose_user(users_path, cert_dir, specified_user):
    users = []
    for _, entry in read_yaml_entries(users_path):
        name = str(entry.get("name", ""))
        if (
            name
            and Path(name).name == name
            and enabled(entry.get("enabled", False))
            and (cert_dir / f"{name}.p12").is_file()
        ):
            if name not in users:
                users.append(name)
    if specified_user:
        if specified_user not in users:
            fail(
                f"Utente '{specified_user}' non abilitato o certificato .p12 mancante."
            )
        return specified_user
    if not users:
        fail("Nessun utente abilitato con certificato .p12 trovato.")
    return choose("Scegli l'utente", [(name, name) for name in users])


def find_ca(ca_override, settings, ca_dir):
    if ca_override:
        path = ca_override
    elif settings.get("CA_FILENAME"):
        path = ca_dir / settings["CA_FILENAME"]
    else:
        candidates = sorted(
            p
            for p in ca_dir.glob("*")
            if p.is_file() and p.suffix.lower() in {".pem", ".crt"}
        )
        if len(candidates) != 1:
            fail("CA non identificabile automaticamente: usa --ca /percorso/cacert.pem")
        path = candidates[0]
    if not path.is_file():
        fail(f"Certificato CA non trovato: {path}")
    contents = path.read_text(encoding="utf-8").strip()
    if (
        "-----BEGIN CERTIFICATE-----" not in contents
        or "-----END CERTIFICATE-----" not in contents
    ):
        fail(f"Il file CA non sembra un certificato PEM: {path}")
    return contents


def make_profile(server, settings, host, ca_pem, p12_name, compression):
    auth = str(server.get("auth_type") or settings.get("AUTH_TYPE") or "").lower()
    if auth not in AUTH_TYPES:
        fail(
            "Metodo di autenticazione non riconosciuto; imposta --auth-type psk|cert|psk_cert"
        )
    if enabled(server.get("disable_encryption", False)):
        fail("L'istanza ha la cifratura disabilitata: esportazione rifiutata.")

    dev = str(server.get("device_type", "")).lower()
    proto = str(server.get("openvpn_protocol", "")).lower()
    port = str(server.get("openvpn_port", ""))
    if dev not in {"tun", "tap"}:
        fail(f"Tipo di device non valido: {dev!r}")
    if proto not in {"udp", "tcp", "tcp-client"}:
        fail(f"Protocollo non valido: {proto!r}")
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        fail(f"Porta OpenVPN non valida: {port!r}")
    if not host or any(char.isspace() for char in host):
        fail("Host VPN non valido: usa --remote con IP o FQDN (senza porta).")

    lines = [
        "client",
        f"dev {dev}",
        f"proto {'tcp-client' if proto == 'tcp' else proto}",
        f"remote {host} {port}",
        "resolv-retry infinite",
        "nobind",
        "persist-key",
        "persist-tun",
        "verb 3",
        "remote-cert-tls server",
    ]
    if auth in {"psk", "psk_cert"}:
        lines.append("auth-user-pass")
    if auth in {"cert", "psk_cert"}:
        if not p12_name:
            fail("Serve un certificato utente PKCS#12 (.p12).")
        lines.append(f"pkcs12 {p12_name}.p12")

    reneg = str(server.get("reneg_sec") or "").strip()
    if reneg and reneg != "3600":
        if not reneg.isdigit():
            fail(f"reneg_sec non valido: {reneg!r}")
        lines.append(f"reneg-sec {reneg}")

    for setting_name, option_name in (("digest", "auth"), ("cipher", "cipher")):
        value = str(server.get(setting_name) or "").strip()
        if value and value.lower() not in {"auto", "default", "none"}:
            if not all(c.isalnum() or c in "-_" for c in value):
                fail(f"Valore {setting_name} non valido: {value!r}")
            lines.append(f"{option_name} {value}")
    if compression:
        lines.append("comp-lzo")
    lines.extend(["<ca>", ca_pem, "</ca>"])
    return "\n".join(lines) + "\n", auth


def safe_write(path, data):
    """Prevent overwrite/symlink replacement and restrict file to its owner."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(data)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--remote",
        required=True,
        help="IP pubblico o DNS raggiungibile della VPN, senza porta",
    )
    parser.add_argument("--output", type=Path, default=Path("endian-client.ovpn"))
    parser.add_argument(
        "--instance", help="ID istanza OpenVPN; altrimenti menu interattivo"
    )
    parser.add_argument(
        "--user", help="Utente con certificato; altrimenti menu interattivo"
    )
    parser.add_argument(
        "--auth-type",
        choices=sorted(AUTH_TYPES),
        help="Sovrascrive il metodo di autenticazione",
    )
    parser.add_argument(
        "--ca", type=Path, help="File PEM della CA (se non rilevato automaticamente)"
    )
    parser.add_argument(
        "--legacy-compression",
        action="store_true",
        help="Aggiunge comp-lzo SOLO se richiesto dal server",
    )
    for key, value in DEFAULTS.items():
        parser.add_argument(
            "--" + key.replace("_", "-"), type=Path, default=Path(value)
        )
    args = parser.parse_args()

    try:
        settings = read_settings(args.settings)
        if settings.get("OPENVPN_ENABLED", "on").strip().lower() != "on":
            fail("Il servizio OpenVPN risulta disabilitato.")
        instance_id, instance = choose_server(args.servers, args.instance)
        if args.auth_type:
            instance["auth_type"] = args.auth_type
        auth = str(instance.get("auth_type") or settings.get("AUTH_TYPE") or "").lower()
        if auth not in AUTH_TYPES:
            fail("AUTH_TYPE non disponibile; usa --auth-type psk|cert|psk_cert")
        username = (
            choose_user(args.users, args.cert_dir, args.user)
            if auth in {"cert", "psk_cert"}
            else None
        )
        ca_pem = find_ca(args.ca, settings, args.ca_dir)
        content, _ = make_profile(
            instance, settings, args.remote, ca_pem, username, args.legacy_compression
        )
        safe_write(args.output, content)
        print(
            f"Profilo creato: {args.output} (istanza {instance_id}, autenticazione {auth})"
        )
        print("Il profilo include la CA, ma NON contiene chiavi private o password.")
        if username:
            print(f"IMPORTANTE: copia anche {args.cert_dir / (username + '.p12')} ")
            print(
                f"             e rinominalo {username}.p12 nella stessa cartella del .ovpn"
            )
        print(
            "Non modificare la configurazione del firewall; verifica la compatibilità del client OpenVPN."
        )
    except (OSError, RuntimeError, yaml.YAMLError) as exc:
        sys.exit(f"ERRORE: {exc}")


if __name__ == "__main__":
    main()
