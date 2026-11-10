#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
IP camera discovery for OpenWrt / Linux.

Discovery probes implemented from the supplied capture:
  * ONVIF WS-Discovery Probe       UDP 239.255.255.250:3702
  * Uniview WS-Discovery extension UDP 255.255.255.255:3702
  * Hikvision/SADP-style Probe     UDP 239.255.255.250 / ff02::c:37020
  * Dahua DVRIP discovery          UDP 255.255.255.255:5050
  * Dahua DHIP discovery           UDP 239.255.255.251:37810/37820/8087

Only Python's standard library is used. On OpenWrt, ElementTree is shipped
by the python3-xml package.
"""

import argparse
import fcntl
import json
import os
import re
import select
import signal
import socket
import struct
import sys
import time
import xml.etree.ElementTree as ET

VERSION = "1.1.6"

WS_DISCOVERY_GROUP = "239.255.255.250"
WS_DISCOVERY_PORT = 3702
WS_DISCOVERY_SOURCE_PORT = 3705
SADP_PORT = 37020
SADP6_GROUP = "ff02::c"
DAHUA_DVRIP_PORT = 5050
DAHUA_DVRIP_SOURCE_PORT = 5051
DAHUA_DHIP_GROUP = "239.255.255.251"
DAHUA_DHIP_ENDPOINTS = (
    (37809, 37810, 1),
    (37810, 37820, 1),
    (37811, 8087, 2),
)
DHIP_HEADER_FORMAT = "<I4sIIIIII"
DHIP_HEADER_SIZE = struct.calcsize(DHIP_HEADER_FORMAT)
SCAN_LOCK_PATH = "/var/run/ipc-discovery.lock"
DEFAULT_SOCKET_PATH = "/var/run/ipc-discovery.sock"

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
ARP_REQUEST = 1
ARP_REPLY = 2
PACKET_OUTGOING = getattr(socket, "PACKET_OUTGOING", 4)
MAX_CLIENT_REQUEST = 4096
MAX_CLIENT_RESPONSE = 8 * 1024 * 1024
MAX_SOCKET_DRAIN = 256
MAX_ACCEPT_BATCH = 16

ACTIVE_CAMERA_PROTOCOLS = frozenset((
    "onvif-wsdiscovery",
    "uniview-wsdiscovery",
    "hikvision-sadp",
    "dahua-dvrip",
    "dahua-dhip",
))
GENERIC_MANUFACTURERS = frozenset(("general", "generic", "private", "unknown"))
DEFAULT_OUI_PATH = "/etc/ipc-discovery/oui-camera.txt"

# Camera-focused OUI hints retained locally so discovery never depends on
# Internet access. An OUI match is vendor metadata only, not proof that the
# device is a camera. Entries in DEFAULT_OUI_PATH override this table.
DEFAULT_CAMERA_OUIS = {
    # Zhejiang Dahua Technology Co., Ltd.
    "08:ed:ed": "Dahua", "14:a7:8b": "Dahua", "24:52:6a": "Dahua",
    "30:dd:aa": "Dahua", "38:af:29": "Dahua", "3c:e3:6b": "Dahua",
    "3c:ef:8c": "Dahua", "40:7a:a4": "Dahua", "4c:11:bf": "Dahua",
    "4c:99:e8": "Dahua", "5c:f5:1a": "Dahua", "64:fd:29": "Dahua",
    "6c:1c:71": "Dahua", "74:c9:29": "Dahua", "8c:e9:b4": "Dahua",
    "90:02:a9": "Dahua", "98:f9:cc": "Dahua", "9c:14:63": "Dahua",
    "a0:bd:1d": "Dahua", "b4:4c:3b": "Dahua", "bc:32:5f": "Dahua",
    "c0:39:5a": "Dahua", "c4:aa:c4": "Dahua", "d4:43:0e": "Dahua",
    "e0:2e:fe": "Dahua", "e0:50:8b": "Dahua", "e4:24:6c": "Dahua",
    "f4:b1:c2": "Dahua", "f8:ce:07": "Dahua", "fc:5f:49": "Dahua",
    # Zhejiang Uniview Technologies Co., Ltd.
    "48:ea:63": "Uniview", "6c:f1:7e": "Uniview",
    "88:26:3f": "Uniview", "c4:79:05": "Uniview",
    # Hangzhou Hikvision Digital Technology Co., Ltd.
    "00:bc:99": "Hikvision", "04:03:12": "Hikvision",
    "04:ee:cd": "Hikvision", "08:3b:c1": "Hikvision",
    "08:54:11": "Hikvision", "08:a1:89": "Hikvision",
    "08:cc:81": "Hikvision", "0c:75:d2": "Hikvision",
    "10:12:fb": "Hikvision", "18:68:cb": "Hikvision",
    "18:80:25": "Hikvision", "24:0f:9b": "Hikvision",
    "24:28:fd": "Hikvision", "24:32:ae": "Hikvision",
    "24:48:45": "Hikvision", "28:57:be": "Hikvision",
    "2c:a5:9c": "Hikvision", "34:09:62": "Hikvision",
    "3c:1b:f8": "Hikvision", "40:ac:bf": "Hikvision",
    "44:19:b6": "Hikvision", "44:47:cc": "Hikvision",
    "44:a6:42": "Hikvision", "48:78:5b": "Hikvision",
    "4c:1f:86": "Hikvision", "4c:62:df": "Hikvision",
    "4c:bd:8f": "Hikvision", "4c:f5:dc": "Hikvision",
    "50:e5:38": "Hikvision", "54:8c:81": "Hikvision",
    "54:c4:15": "Hikvision", "58:03:fb": "Hikvision",
    "58:50:ed": "Hikvision", "5c:34:5b": "Hikvision",
    "64:db:8b": "Hikvision", "68:6d:bc": "Hikvision",
    "74:3f:c2": "Hikvision", "80:48:9f": "Hikvision",
    "80:7c:62": "Hikvision", "80:be:af": "Hikvision",
    "80:f5:ae": "Hikvision", "84:94:59": "Hikvision",
    "84:9a:40": "Hikvision", "88:de:39": "Hikvision",
    "8c:22:d2": "Hikvision", "8c:e7:48": "Hikvision",
    "94:e1:ac": "Hikvision", "98:8b:0a": "Hikvision",
    "98:9d:e5": "Hikvision", "98:df:82": "Hikvision",
    "98:f1:12": "Hikvision", "a0:ff:0c": "Hikvision",
    "a4:14:37": "Hikvision", "a4:29:02": "Hikvision",
    "a4:4b:d9": "Hikvision", "a4:a4:59": "Hikvision",
    "a4:d5:c2": "Hikvision", "ac:b9:2f": "Hikvision",
    "ac:cb:51": "Hikvision", "b4:a3:82": "Hikvision",
    "bc:5e:33": "Hikvision", "bc:9b:5e": "Hikvision",
    "bc:ad:28": "Hikvision", "bc:ba:c2": "Hikvision",
    "c0:51:7e": "Hikvision", "c0:56:e3": "Hikvision",
    "c0:6d:ed": "Hikvision", "c4:2f:90": "Hikvision",
    "c8:a7:02": "Hikvision", "cc:13:f3": "Hikvision",
    "d4:e8:53": "Hikvision", "dc:07:f8": "Hikvision",
    "dc:d2:6a": "Hikvision", "e0:ba:ad": "Hikvision",
    "e0:ca:3c": "Hikvision", "e0:df:13": "Hikvision",
    "e4:d5:8b": "Hikvision", "e8:a0:ed": "Hikvision",
    "ec:a9:71": "Hikvision", "ec:c8:9c": "Hikvision",
    "f8:4d:fc": "Hikvision", "fc:9f:fd": "Hikvision",
    # Prama Hikvision India
    "24:b1:05": "Prama Hikvision", "bc:29:78": "Prama Hikvision",
}

SIOCGIFFLAGS = 0x8913
SIOCGIFADDR = 0x8915
SIOCGIFBRDADDR = 0x8919
SIOCGIFNETMASK = 0x891B
IFF_UP = 0x1
IFF_LOOPBACK = 0x8

SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)


class DiscoveryError(Exception):
    pass


def _acquire_scan_lock():
    """Prevent overlapping LuCI/CLI scans and duplicate broadcast bursts."""
    try:
        handle = open(SCAN_LOCK_PATH, "a+")
    except OSError as exc:
        raise DiscoveryError("cannot open scan lock %s: %s" % (SCAN_LOCK_PATH, exc))
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        raise DiscoveryError("another IP camera discovery scan is already running")
    return handle


def _stderr(message):
    print(message, file=sys.stderr)


def _uuid4_text(upper=False):
    """Generate an RFC 4122 version-4 UUID without importing python3-uuid."""
    value = bytearray(os.urandom(16))
    value[6] = (value[6] & 0x0F) | 0x40
    value[8] = (value[8] & 0x3F) | 0x80
    text = (
        value[0:4].hex() + "-" +
        value[4:6].hex() + "-" +
        value[6:8].hex() + "-" +
        value[8:10].hex() + "-" +
        value[10:16].hex()
    )
    return text.upper() if upper else text


def _ifreq(interface):
    encoded = interface.encode("ascii", "strict")
    if not encoded or len(encoded) > 15:
        raise DiscoveryError("interface name must contain 1 to 15 ASCII bytes")
    return struct.pack("256s", encoded)


def _ioctl_ipv4(interface, request):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        result = fcntl.ioctl(sock.fileno(), request, _ifreq(interface))
    return socket.inet_ntoa(result[20:24])


def _interface_flags(interface):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        result = fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, _ifreq(interface))
    return struct.unpack_from("H", result, 16)[0]


def _calculate_broadcast(address, netmask):
    address_i = struct.unpack("!I", socket.inet_aton(address))[0]
    mask_i = struct.unpack("!I", socket.inet_aton(netmask))[0]
    return socket.inet_ntoa(struct.pack("!I", address_i | (~mask_i & 0xFFFFFFFF)))


def _interface_mac(interface):
    try:
        with open("/sys/class/net/%s/address" % interface, "r") as handle:
            value = handle.read().strip().lower()
    except OSError:
        return ""
    return _normalize_mac(value)


def _interface_details(interface):
    try:
        flags = _interface_flags(interface)
        address = _ioctl_ipv4(interface, SIOCGIFADDR)
        netmask = _ioctl_ipv4(interface, SIOCGIFNETMASK)
        try:
            broadcast = _ioctl_ipv4(interface, SIOCGIFBRDADDR)
        except OSError:
            broadcast = _calculate_broadcast(address, netmask)
    except (OSError, UnicodeError) as exc:
        raise DiscoveryError("cannot inspect interface %s: %s" % (interface, exc))

    if not flags & IFF_UP:
        raise DiscoveryError("interface %s is down" % interface)
    if flags & IFF_LOOPBACK:
        raise DiscoveryError("interface %s is loopback" % interface)
    if address == "0.0.0.0":
        raise DiscoveryError("interface %s has no usable IPv4 address" % interface)
    if broadcast == "0.0.0.0":
        broadcast = _calculate_broadcast(address, netmask)

    return {
        "name": interface,
        "address": address,
        "netmask": netmask,
        "broadcast": broadcast,
        "mac": _interface_mac(interface),
    }


def _available_interfaces():
    try:
        names = os.listdir("/sys/class/net")
    except OSError:
        names = []

    details = []
    for name in names:
        if name == "lo":
            continue
        try:
            details.append(_interface_details(name))
        except DiscoveryError:
            pass
    return details


def _select_interface(requested=None):
    if requested:
        return _interface_details(requested)

    available = _available_interfaces()
    if not available:
        raise DiscoveryError("no UP, non-loopback interface with an IPv4 address was found")

    # On OpenWrt, br-lan is normally the correct L3 device. Keep the fallback
    # deterministic, preferring bridge/LAN names over WAN-like names.
    preferred_exact = ["br-lan", "lan", "eth0"]

    def rank(item):
        name = item["name"]
        if name in preferred_exact:
            return (0, preferred_exact.index(name), name)
        if name.startswith("br-lan"):
            return (1, 0, name)
        if name.startswith("br-"):
            return (2, 0, name)
        if name.startswith("lan"):
            return (3, 0, name)
        if name.startswith(("wan", "wwan", "ppp")):
            return (9, 0, name)
        return (5, 0, name)

    return sorted(available, key=rank)[0]


def _bind_to_device(sock, interface, warnings):
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, interface.encode() + b"\0")
    except PermissionError:
        warnings.append(
            "SO_BINDTODEVICE was denied; run as root to guarantee interface isolation"
        )
    except OSError as exc:
        warnings.append("SO_BINDTODEVICE(%s) failed: %s" % (interface, exc))


def _common_socket_options(sock, interface, warnings):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
    except OSError:
        pass
    _bind_to_device(sock, interface, warnings)


def _make_onvif_socket(interface, local_address, warnings):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        _common_socket_options(sock, interface, warnings)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_address))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        # The capture shows cameras returning fragmented UDP datagrams to the
        # limited-broadcast address on source port 3705. Binding 0.0.0.0 is
        # intentional so both unicast and broadcast replies are accepted.
        sock.bind(("", WS_DISCOVERY_SOURCE_PORT))
        sock.setblocking(False)
        return sock
    except Exception:
        sock.close()
        raise


def _make_sadp_socket(interface, local_address, warnings):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        _common_socket_options(sock, interface, warnings)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_address))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        sock.bind(("", SADP_PORT))
        membership = socket.inet_aton(WS_DISCOVERY_GROUP) + socket.inet_aton(local_address)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        sock.setblocking(False)
        return sock
    except Exception:
        sock.close()
        raise


def _make_sadp6_socket(interface, warnings):
    if not hasattr(socket, "AF_INET6"):
        raise OSError("IPv6 is not available")
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        except OSError:
            pass
        _bind_to_device(sock, interface, warnings)
        interface_index = socket.if_nametoindex(interface)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, interface_index)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
        sock.bind(("::", SADP_PORT))
        membership = (
            socket.inet_pton(socket.AF_INET6, SADP6_GROUP) +
            struct.pack("@I", interface_index)
        )
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, membership)
        sock.setblocking(False)
        return sock
    except Exception:
        sock.close()
        raise


def _make_dahua_socket(interface, local_address, source_port, warnings):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        # These are reply sockets, not shared multicast listeners. Keep the
        # preferred source ports exclusive so another discovery process cannot
        # nondeterministically consume our unicast replies. If a port is busy,
        # bind an ephemeral port below instead.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        except OSError:
            pass
        _bind_to_device(sock, interface, warnings)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_address))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        try:
            sock.bind(("", source_port))
        except OSError as exc:
            warnings.append(
                "Dahua UDP/%d could not be bound; using a temporary source port: %s" %
                (source_port, exc)
            )
            sock.bind(("", 0))
        sock.setblocking(False)
        return sock
    except Exception:
        sock.close()
        raise


def _make_layer2_socket(interface):
    if not hasattr(socket, "AF_PACKET"):
        raise OSError("AF_PACKET is not available on this platform")
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    try:
        sock.bind((interface, 0))
        sock.setblocking(False)
        return sock
    except Exception:
        sock.close()
        raise


def _open_discovery_sockets(args):
    interface = _select_interface(args.interface)
    warnings = []
    sockets = {}

    if not args.no_onvif:
        try:
            sockets["onvif"] = _make_onvif_socket(
                interface["name"], interface["address"], warnings
            )
        except OSError as exc:
            warnings.append(
                "ONVIF listener UDP/%d could not be opened: %s" %
                (WS_DISCOVERY_SOURCE_PORT, exc)
            )

    if not args.no_sadp:
        try:
            sockets["sadp"] = _make_sadp_socket(
                interface["name"], interface["address"], warnings
            )
        except OSError as exc:
            warnings.append(
                "SADP listener UDP/%d could not be opened: %s" % (SADP_PORT, exc)
            )
        try:
            sockets["sadp6"] = _make_sadp6_socket(interface["name"], warnings)
        except (OSError, AttributeError) as exc:
            warnings.append("SADP IPv6 listener could not be opened: %s" % exc)

    if not args.no_dahua:
        try:
            sockets["dahua-dvrip"] = _make_dahua_socket(
                interface["name"], interface["address"],
                DAHUA_DVRIP_SOURCE_PORT, warnings,
            )
        except OSError as exc:
            warnings.append("Dahua DVRIP listener could not be opened: %s" % exc)
        for source_port, _destination_port, _repeat in DAHUA_DHIP_ENDPOINTS:
            try:
                sockets["dahua-dhip-%d" % source_port] = _make_dahua_socket(
                    interface["name"], interface["address"], source_port, warnings
                )
            except OSError as exc:
                warnings.append(
                    "Dahua DHIP listener UDP/%d could not be opened: %s" %
                    (source_port, exc)
                )

    try:
        sockets["layer2"] = _make_layer2_socket(interface["name"])
    except OSError as exc:
        warnings.append("ARP/DHCP listener could not be opened: %s" % exc)

    if not sockets:
        raise DiscoveryError("no discovery listener could be opened")
    return interface, warnings, sockets


def _new_stats():
    return {
        "probes_sent": 0,
        "datagrams_received": 0,
        "datagrams_ignored": 0,
        "arp_packets": 0,
        "dhcp_packets": 0,
    }


def _stats_delta(current, baseline=None):
    if baseline is None:
        baseline = {}
    return {
        key: max(0, value - baseline.get(key, 0))
        for key, value in current.items()
    }


def _drain_discovery_socket(sock, protocol, interface, stats, warnings):
    devices = []
    # Bound each readiness pass so sustained AF_PACKET or multicast traffic
    # cannot starve daemon commands, scan deadlines, or the other sockets.
    for _packet_number in range(MAX_SOCKET_DRAIN):
        try:
            payload, peer = sock.recvfrom(65535)
        except BlockingIOError:
            break
        except OSError as exc:
            warnings.append("receive failed on %s: %s" % (protocol, exc))
            break

        now_ms = int(time.time() * 1000)
        if protocol == "layer2":
            if len(peer) > 2 and peer[2] == PACKET_OUTGOING:
                continue
            frame_protocol, device = parse_layer2_frame(payload, now_ms=now_ms)
            if not device:
                continue
            if interface.get("mac") and device.get("mac") == interface["mac"]:
                continue
            stats[frame_protocol + "_packets"] += 1
            devices.append(device)
            continue

        stats["datagrams_received"] += 1
        parsed = parse_discovery_payload(
            payload, source_ip=peer[0], now_ms=now_ms
        )
        if not parsed:
            stats["datagrams_ignored"] += 1
            continue
        devices.extend(parsed)
    return devices


def _probe_payloads():
    message_id = "urn:uuid:" + _uuid4_text()
    return {
        "onvif": _onvif_probe(message_id, uniview=False),
        "uniview": _onvif_probe(message_id, uniview=True),
        "sadp": _sadp_probe(_uuid4_text(upper=True)),
        "dahua-dvrip": _dahua_dvrip_probe(),
        "dahua-dhip": _dahua_dhip_probe(),
    }


def _close_sockets(sockets):
    for sock in sockets.values():
        try:
            sock.close()
        except OSError:
            pass


def _onvif_probe(message_id, uniview=False):
    body_name = "UniviewProbe" if uniview else "Probe"
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<SOAP-ENV:Envelope '
        'xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
        'xmlns:xop="http://www.w3.org/2004/08/xop/include" '
        'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:tns="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl" '
        'xmlns:wsa5="http://www.w3.org/2005/08/addressing">'
        '<SOAP-ENV:Header>'
        '<wsa:MessageID>%s</wsa:MessageID>'
        '<wsa:To SOAP-ENV:mustUnderstand="true">'
        'urn:schemas-xmlsoap-org:ws:2005:04:discovery'
        '</wsa:To>'
        '<wsa:Action SOAP-ENV:mustUnderstand="true">'
        'http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe'
        '</wsa:Action>'
        '</SOAP-ENV:Header>'
        '<SOAP-ENV:Body>'
        '<tns:%s><tns:Types>dn:NetworkVideoTransmitter</tns:Types></tns:%s>'
        '</SOAP-ENV:Body>'
        '</SOAP-ENV:Envelope>'
    ) % (message_id, body_name, body_name)
    return xml.encode("utf-8")


def _sadp_probe(probe_uuid):
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<Probe><Uuid>%s</Uuid><Types>inquiry</Types>'
        '<ResponseMode>2</ResponseMode></Probe>'
    ) % probe_uuid
    return xml.encode("utf-8")


def _dahua_dvrip_probe():
    # ConfigTool's legacy discovery request is a fixed 32-byte A3 frame.
    return bytes.fromhex(
        "a3010001000000000000000000000000"
        "02000000000000000000000000000000"
    )


def _dahua_dhip_probe():
    # Preserve ConfigTool's JSON whitespace so the generated datagram is
    # byte-aligned with the supplied customer capture.
    body = (
        b'{ "method" : "DHDiscover.search", '
        b'"params" : { "mac" : "", "uni" : 1 } }\n'
    )
    header = struct.pack(
        DHIP_HEADER_FORMAT,
        DHIP_HEADER_SIZE,
        b"DHIP",
        0,
        0,
        len(body),
        0,
        len(body),
        0,
    )
    return header + body


def _local_name(tag):
    if "}" in tag:
        tag = tag.rsplit("}", 1)[1]
    if ":" in tag:
        tag = tag.rsplit(":", 1)[1]
    return tag


def _texts(root, local_name):
    result = []
    for element in root.iter():
        if _local_name(element.tag) != local_name:
            continue
        text = "".join(element.itertext()).strip()
        if text:
            result.append(text)
    return result


def _first_text(root, local_name, default=""):
    values = _texts(root, local_name)
    return values[0] if values else default


def _percent_decode(value):
    output = bytearray()
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "%" and i + 2 < len(value):
            pair = value[i + 1:i + 3]
            try:
                output.append(int(pair, 16))
                i += 3
                continue
            except ValueError:
                pass
        output.extend(ch.encode("utf-8"))
        i += 1
    return output.decode("utf-8", "replace")


def _parse_scopes(scope_texts):
    raw = []
    values = {}
    prefixes = (
        "onvif://www.onvif.org/",
        "http://www.onvif.org/",
        "https://www.onvif.org/",
    )

    for scope_text in scope_texts:
        for uri in scope_text.split():
            raw.append(uri)
            rest = None
            for prefix in prefixes:
                if uri.startswith(prefix):
                    rest = uri[len(prefix):]
                    break
            if rest is None:
                continue
            if "/" in rest:
                key, value = rest.split("/", 1)
            else:
                key, value = rest, ""
            key = _percent_decode(key).lower()
            value = _percent_decode(value)
            values.setdefault(key, []).append(value)

    return raw, values


def _scope_first(scopes, *keys):
    for key in keys:
        values = scopes.get(key.lower())
        if values:
            return values[0]
    return ""


def _normalize_mac(value):
    compact = re.sub(r"[^0-9A-Fa-f]", "", value or "")
    if len(compact) != 12:
        return ""
    compact = compact.lower()
    return ":".join(compact[i:i + 2] for i in range(0, 12, 2))


def _normalize_oui(value):
    compact = re.sub(r"[^0-9A-Fa-f]", "", value or "")
    if len(compact) != 6:
        return ""
    compact = compact.lower()
    return ":".join(compact[i:i + 2] for i in range(0, 6, 2))


def load_camera_ouis(path=DEFAULT_OUI_PATH):
    """Load built-in camera OUIs plus optional PREFIX|VENDOR overrides."""
    database = dict(DEFAULT_CAMERA_OUIS)
    if not path:
        return database
    try:
        handle = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return database
    try:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "|" not in line:
                continue
            prefix, vendor = line.split("|", 1)
            prefix = _normalize_oui(prefix)
            vendor = vendor.strip()[:128]
            if prefix and vendor:
                database[prefix] = vendor
    finally:
        handle.close()
    return database


def oui_vendor(mac, database):
    normalized = _normalize_mac(mac)
    return database.get(normalized[:8], "") if normalized else ""


def _apply_oui_metadata(device, database):
    vendor = oui_vendor(device.get("mac"), database)
    if not vendor:
        if device.get("manufacturer") and not device.get("manufacturer_source"):
            device["manufacturer_source"] = "protocol"
        return
    device["oui_vendor"] = vendor
    if not device.get("manufacturer"):
        device["manufacturer"] = vendor
        device["manufacturer_source"] = "mac-oui"
    elif not device.get("manufacturer_source"):
        device["manufacturer_source"] = "protocol"


def _as_bool(value):
    if value is None or value == "":
        return None
    return str(value).strip().lower() in ("1", "true", "yes", "on", "enabled")


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_url_host(url):
    # Deliberately small URL parser to avoid the split python3-urllib package.
    match = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://(\[[^]]+\]|[^/:?#]+)(?::([0-9]+))?", url)
    if not match:
        return "", None
    host = match.group(1)
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    port = _as_int(match.group(2))
    return host, port


def _is_ipv4(value):
    try:
        socket.inet_aton(value)
    except (OSError, TypeError):
        return False
    return isinstance(value, str) and value.count(".") == 3


def _empty_device(protocol, source_ip, now_ms):
    return {
        "protocols": [protocol],
        "ip": "",
        "mac": "",
        "manufacturer": "",
        "manufacturer_source": "",
        "oui_vendor": "",
        "model": "",
        "name": "",
        "serial": "",
        "firmware": "",
        "endpoint": "",
        "xaddrs": [],
        "web_url": "",
        "http_port": None,
        "command_port": None,
        "activated": None,
        "dhcp": None,
        "subnet_mask": "",
        "gateway": "",
        "video_sources": None,
        "device_types": [],
        "scopes": [],
        "metadata_version": None,
        "source_ips": [source_ip] if source_ip else [],
        "first_seen_ms": now_ms,
        "last_seen_ms": now_ms,
        "responses": 1,
    }


def _packed_ipv4(value):
    if not isinstance(value, (bytes, bytearray)) or len(value) != 4:
        return ""
    try:
        address = socket.inet_ntoa(bytes(value))
    except OSError:
        return ""
    return "" if address == "0.0.0.0" else address


def _parse_dahua_dvrip(payload, source_ip, now_ms):
    # A legacy Dahua discovery response has a 32-byte B3 header, an 88-byte
    # fixed binary record, and an optional text trailer. The offsets below
    # match both ConfigTool's capture and the live customer device response.
    if len(payload) < 120 or payload[:2] != b"\xb3\x00":
        return []

    body = payload[32:]
    fixed = body[:88]
    trailer = body[88:].rstrip(b"\0")
    mac_match = re.search(
        br"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", trailer
    )
    if not mac_match:
        return []

    mac = _normalize_mac(mac_match.group(0).decode("ascii"))
    remainder = trailer[mac_match.end():]
    name_marker = remainder.find(b"Name:")
    if name_marker >= 0:
        model_bytes = remainder[:name_marker]
        text_bytes = remainder[name_marker:]
    else:
        model_bytes = b""
        text_bytes = remainder

    model = model_bytes.decode("utf-8", "replace").strip("\0\r\n ")
    text_fields = {}
    for raw_line in text_bytes.decode("utf-8", "replace").splitlines():
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        text_fields[key.strip()] = value.strip()

    version_parts = struct.unpack_from("<HHHH", fixed, 0)
    binary_version = ".".join(str(part) for part in version_parts)
    address = _packed_ipv4(fixed[24:28]) or source_ip
    http_port = struct.unpack_from("<H", fixed, 62)[0] or None
    command_port = _as_int(text_fields.get("Port"))
    if command_port is None:
        command_port = struct.unpack_from("<H", fixed, 66)[0] or None

    serial = text_fields.get("SerialNo", "")
    device = _empty_device("dahua-dvrip", source_ip, now_ms)
    device.update({
        "ip": address,
        "mac": mac,
        "manufacturer": "Dahua",
        "manufacturer_source": "protocol",
        "model": model or text_fields.get("Device", ""),
        "name": text_fields.get("Name", ""),
        "serial": serial,
        "firmware": text_fields.get("Version", "") or binary_version,
        "endpoint": text_fields.get("DeviceID", "") or serial,
        "http_port": http_port,
        "command_port": command_port,
        "subnet_mask": _packed_ipv4(fixed[28:32]),
        "gateway": _packed_ipv4(fixed[32:36]),
        "device_types": [text_fields["Device"]] if text_fields.get("Device") else [],
    })
    if device["ip"] and http_port:
        device["web_url"] = "http://%s:%d/" % (device["ip"], http_port)
    return [device]


def _parse_dahua_dhip(payload, source_ip, now_ms):
    if len(payload) < DHIP_HEADER_SIZE:
        return []
    try:
        (header_size, magic, _session_id, _request_id, package_length,
         _package_index, message_length, data_length) = struct.unpack_from(
            DHIP_HEADER_FORMAT, payload, 0
        )
    except struct.error:
        return []
    if header_size != DHIP_HEADER_SIZE or magic != b"DHIP":
        return []
    if message_length <= 0 or package_length != message_length + data_length:
        return []
    if package_length > len(payload) - header_size:
        return []

    json_bytes = payload[header_size:header_size + message_length]
    try:
        message = json.loads(json_bytes.rstrip(b"\0\r\n ").decode("utf-8"))
    except (UnicodeError, ValueError):
        return []
    if not isinstance(message, dict) or message.get("method") not in (
        "client.notifyDevInfo", "client.notifyDeviceInfo"
    ):
        return []
    params = message.get("params")
    if not isinstance(params, dict):
        return []
    info = params.get("deviceInfo")
    if not isinstance(info, dict):
        return []

    ipv4 = info.get("IPv4Address")
    if not isinstance(ipv4, dict):
        ipv4 = {}
    address = ipv4.get("IPAddress") if _is_ipv4(ipv4.get("IPAddress", "")) else source_ip
    mac = _normalize_mac(message.get("mac") or info.get("MAC") or "")
    if not (address or mac or info.get("SerialNo")):
        return []

    manufacturer = info.get("Manufacturer") or info.get("Vendor") or "Dahua"
    http_port = _as_int(info.get("HttpPort"))
    command_port = _as_int(info.get("Port"))
    serial = str(info.get("SerialNo") or "")
    device_type = str(info.get("DeviceType") or info.get("DeviceClass") or "")
    device = _empty_device("dahua-dhip", source_ip, now_ms)
    device.update({
        "ip": address,
        "mac": mac,
        "manufacturer": str(manufacturer),
        "manufacturer_source": "protocol",
        "model": device_type,
        "name": str(info.get("MachineName") or ""),
        "serial": serial,
        "firmware": str(info.get("Version") or ""),
        "endpoint": str(info.get("DeviceID") or serial),
        "http_port": http_port,
        "command_port": command_port,
        "dhcp": _as_bool(ipv4.get("DhcpEnable")),
        "subnet_mask": str(ipv4.get("SubnetMask") or ""),
        "gateway": str(ipv4.get("DefaultGateway") or ""),
        "video_sources": _as_int(info.get("VideoInputChannels")),
        "device_types": [str(info["DeviceClass"])] if info.get("DeviceClass") else [],
    })
    if address and http_port:
        device["web_url"] = "http://%s:%d/" % (address, http_port)
    return [device]


def _parse_sadp(root, source_ip, now_ms):
    # A SADP response in the supplied capture is ProbeMatch in the ISAPI
    # namespace and carries DeviceSN/IPv4Address. Do not misclassify ONVIF's
    # nested ProbeMatch elements.
    if _local_name(root.tag) != "ProbeMatch":
        return []
    if not (_first_text(root, "DeviceSN") or _first_text(root, "IPv4Address")):
        return []

    device = _empty_device("hikvision-sadp", source_ip, now_ms)
    device.update({
        "ip": _first_text(root, "IPv4Address") or source_ip,
        "mac": _normalize_mac(_first_text(root, "MAC")),
        "model": _first_text(root, "DeviceType") or _first_text(root, "DeviceDescription"),
        "name": _first_text(root, "DeviceDescription"),
        "serial": _first_text(root, "DeviceSN"),
        "firmware": _first_text(root, "SoftwareVersion"),
        "endpoint": _first_text(root, "Uuid"),
        "http_port": _as_int(_first_text(root, "HttpPort")),
        "command_port": _as_int(_first_text(root, "CommandPort")),
        "activated": _as_bool(_first_text(root, "Activated")),
        "dhcp": _as_bool(_first_text(root, "DHCP")),
        "subnet_mask": _first_text(root, "IPv4SubnetMask"),
        "gateway": _first_text(root, "IPv4Gateway"),
    })
    if device["ip"] and device["http_port"]:
        device["web_url"] = "http://%s:%d/" % (device["ip"], device["http_port"])
    return [device]


def _parse_onvif(root, source_ip, now_ms):
    action = _first_text(root, "Action")
    has_uniview = "UniviewProbeMatches" in action or any(
        _local_name(element.tag) == "UniviewProbeMatches" for element in root.iter()
    )
    protocol = "uniview-wsdiscovery" if has_uniview else "onvif-wsdiscovery"

    probe_matches = [
        element for element in root.iter()
        if _local_name(element.tag) == "ProbeMatch"
    ]
    if not probe_matches:
        return []

    header_message_id = _first_text(root, "MessageID")
    devices = []
    for match in probe_matches:
        xaddrs = []
        for value in _texts(match, "XAddrs"):
            xaddrs.extend(value.split())
        raw_scopes, scopes = _parse_scopes(_texts(match, "Scopes"))

        endpoint = _first_text(match, "Address")
        types = []
        for value in _texts(match, "Types"):
            types.extend(value.split())

        host = ""
        url_port = None
        for url in xaddrs:
            candidate_host, candidate_port = _extract_url_host(url)
            if candidate_host:
                host = candidate_host
                url_port = candidate_port
                if _is_ipv4(candidate_host):
                    break

        device = _empty_device(protocol, source_ip, now_ms)
        device.update({
            "ip": host if _is_ipv4(host) else source_ip,
            "mac": _normalize_mac(_scope_first(scopes, "macaddr", "mac")),
            "manufacturer": _scope_first(scopes, "manufacturer", "vendor"),
            "model": _scope_first(scopes, "hardware", "model"),
            "name": _scope_first(scopes, "name"),
            "serial": _scope_first(scopes, "serial", "serialnumber"),
            "firmware": _scope_first(scopes, "version", "firmware"),
            "endpoint": endpoint or header_message_id,
            "xaddrs": xaddrs,
            "web_url": xaddrs[0] if xaddrs else "",
            "http_port": url_port,
            "video_sources": _as_int(_scope_first(scopes, "videosourcenumber")),
            "device_types": types,
            "scopes": raw_scopes,
            "metadata_version": _as_int(_first_text(match, "MetadataVersion")),
        })
        if device["manufacturer"]:
            device["manufacturer_source"] = "protocol"
        devices.append(device)

    return devices


def parse_discovery_payload(payload, source_ip="", now_ms=None):
    """Parse one UDP payload and return zero or more normalized devices."""
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    if not payload or len(payload) > 65535:
        return []
    dvrip = _parse_dahua_dvrip(payload, source_ip, now_ms)
    if dvrip:
        return dvrip
    dhip = _parse_dahua_dhip(payload, source_ip, now_ms)
    if dhip:
        return dhip
    # Avoid ElementTree work for unrelated UDP datagrams on shared ports.
    stripped = payload.lstrip()
    if not stripped.startswith(b"<"):
        return []
    try:
        root = ET.fromstring(payload)
    except (ET.ParseError, ValueError):
        return []

    sadp = _parse_sadp(root, source_ip, now_ms)
    if sadp:
        return sadp
    return _parse_onvif(root, source_ip, now_ms)


def _format_mac(value):
    if not isinstance(value, (bytes, bytearray)) or len(value) != 6:
        return ""
    return ":".join("%02x" % byte for byte in value)


def _ethernet_payload(frame):
    """Return (ethertype, payload offset) for Ethernet and VLAN frames."""
    if len(frame) < 14:
        return None, None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    while ethertype in (ETH_P_8021Q, ETH_P_8021AD):
        if len(frame) < offset + 4:
            return None, None
        ethertype = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
        offset += 4
    return ethertype, offset


def _parse_arp_frame(frame, payload_offset, now_ms):
    if len(frame) < payload_offset + 28:
        return None
    arp = frame[payload_offset:payload_offset + 28]
    htype, ptype, hlen, plen, operation = struct.unpack("!HHBBH", arp[:8])
    if (
        htype != 1 or ptype != ETH_P_IP or hlen != 6 or plen != 4 or
        operation not in (ARP_REQUEST, ARP_REPLY)
    ):
        return None
    sender_mac = _format_mac(arp[8:14])
    sender_ip = socket.inet_ntoa(arp[14:18])
    if not sender_mac or sender_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return None
    if sender_ip == "0.0.0.0" or sender_ip.startswith(("224.", "239.")):
        return None

    device = _empty_device("arp", sender_ip, now_ms)
    device["ip"] = sender_ip
    device["mac"] = sender_mac
    return device


def _dhcp_options(data):
    message_type = None
    requested_ip = ""
    offset = 0
    while offset < len(data):
        code = data[offset]
        offset += 1
        if code == 0:
            continue
        if code == 255:
            break
        if offset >= len(data):
            break
        length = data[offset]
        offset += 1
        if offset + length > len(data):
            break
        value = data[offset:offset + length]
        offset += length
        if code == 53 and length == 1:
            message_type = value[0]
        elif code == 50 and length == 4:
            requested_ip = socket.inet_ntoa(value)
    return message_type, requested_ip


def _parse_dhcp_frame(frame, payload_offset, now_ms):
    ip = frame[payload_offset:]
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl + 8 or ip[9] != socket.IPPROTO_UDP:
        return None
    fragment = struct.unpack("!H", ip[6:8])[0]
    if fragment & 0x3FFF:
        return None
    total_length = struct.unpack("!H", ip[2:4])[0]
    if total_length < ihl + 8 or len(ip) < total_length:
        return None
    source_port, destination_port, udp_length, _ = struct.unpack(
        "!HHHH", ip[ihl:ihl + 8]
    )
    if source_port != 68 or destination_port != 67 or udp_length < 8 + 240:
        return None
    bootp_end = min(total_length, ihl + udp_length)
    bootp = ip[ihl + 8:bootp_end]
    if len(bootp) < 240 or bootp[0] != 1 or bootp[1] != 1 or bootp[2] != 6:
        return None
    if bootp[236:240] != b"\x63\x82\x53\x63":
        return None
    message_type, requested_ip = _dhcp_options(bootp[240:])
    if message_type != 1:
        return None
    client_mac = _format_mac(bootp[28:34])
    if not client_mac or client_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return None
    client_ip = socket.inet_ntoa(bootp[12:16])
    if client_ip == "0.0.0.0":
        client_ip = requested_ip

    device = _empty_device("dhcp", client_ip, now_ms)
    device["ip"] = client_ip
    device["mac"] = client_mac
    device["dhcp"] = True
    return device


def parse_layer2_frame(frame, now_ms=None):
    """Parse one raw Ethernet frame into (protocol, device)."""
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    ethertype, payload_offset = _ethernet_payload(frame)
    if ethertype == ETH_P_ARP:
        device = _parse_arp_frame(frame, payload_offset, now_ms)
        return ("arp", device) if device else (None, None)
    if ethertype == ETH_P_IP:
        device = _parse_dhcp_frame(frame, payload_offset, now_ms)
        return ("dhcp", device) if device else (None, None)
    return None, None


def _same_device(left, right):
    if left.get("mac") and right.get("mac"):
        return left["mac"] == right["mac"]
    if left.get("serial") and right.get("serial") and left["serial"] == right["serial"]:
        return True
    if left.get("endpoint") and right.get("endpoint") and left["endpoint"] == right["endpoint"]:
        return True
    if left.get("ip") and right.get("ip") and left["ip"] == right["ip"]:
        return True
    return False


def _merge_unique(target, values):
    for value in values or []:
        if value and value not in target:
            target.append(value)


def _manufacturer_rank(value, source):
    if not value:
        return 0
    if str(value).strip().lower() in GENERIC_MANUFACTURERS:
        return 1
    return 3 if source == "protocol" else 2


def _merge_device(target, incoming):
    target_last_seen = target.get("last_seen_ms", 0)
    incoming_last_seen = incoming.get("last_seen_ms", 0)
    _merge_unique(target["protocols"], incoming.get("protocols"))
    for key in ("xaddrs", "device_types", "scopes", "source_ips"):
        _merge_unique(target[key], incoming.get(key))

    target["responses"] += incoming.get("responses", 1)
    target["first_seen_ms"] = min(target["first_seen_ms"], incoming["first_seen_ms"])
    target["last_seen_ms"] = max(target["last_seen_ms"], incoming["last_seen_ms"])

    scalar_fields = (
        "ip", "mac", "oui_vendor", "model", "name", "serial", "firmware",
        "endpoint", "web_url", "http_port", "command_port", "activated", "dhcp",
        "subnet_mask", "gateway", "video_sources", "metadata_version",
    )
    for key in scalar_fields:
        current = target.get(key)
        incoming_value = incoming.get(key)
        if (
            key == "ip" and incoming_value not in (None, "", []) and
            incoming_last_seen >= target_last_seen
        ):
            target[key] = incoming_value
        elif current in (None, "", []) and incoming_value not in (None, "", []):
            target[key] = incoming_value

    incoming_manufacturer = incoming.get("manufacturer")
    incoming_source = incoming.get("manufacturer_source")
    current_manufacturer = target.get("manufacturer")
    current_source = target.get("manufacturer_source")
    if _manufacturer_rank(incoming_manufacturer, incoming_source) > _manufacturer_rank(
        current_manufacturer, current_source
    ):
        target["manufacturer"] = incoming_manufacturer
        target["manufacturer_source"] = incoming_source or "protocol"


def _insert_device(devices, incoming):
    primary = None
    for current in devices:
        if _same_device(current, incoming):
            _merge_device(current, incoming)
            primary = current
            break
    if primary is None:
        devices.append(incoming)
        return

    # The incoming record may bridge entries that could not previously be
    # associated (for example, one has serial+IP and another has MAC+new IP).
    # Coalesce every newly matching entry so merge results do not depend on
    # socket arrival order. Restart after each merge because identity grows.
    changed = True
    while changed:
        changed = False
        for index, current in enumerate(devices):
            if current is primary or not _same_device(primary, current):
                continue
            _merge_device(primary, current)
            devices.pop(index)
            changed = True
            break


class DeviceCache:
    def __init__(self, online_window=60.0, cache_ttl=300.0, max_entries=4096,
                 oui_db=None):
        self.online_window_ms = int(online_window * 1000)
        self.cache_ttl_ms = int(cache_ttl * 1000)
        self.max_entries = max_entries
        self.oui_db = load_camera_ouis() if oui_db is None else dict(oui_db)
        self.devices = []

    def observe(self, incoming):
        _apply_oui_metadata(incoming, self.oui_db)
        _insert_device(self.devices, incoming)
        if len(self.devices) > self.max_entries:
            self.devices.sort(key=lambda item: item.get("last_seen_ms", 0), reverse=True)
            del self.devices[self.max_entries:]

    def prune(self, now_ms=None):
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        cutoff = now_ms - self.cache_ttl_ms
        self.devices = [
            device for device in self.devices
            if device.get("last_seen_ms", 0) >= cutoff
        ]

    def clear(self):
        count = len(self.devices)
        self.devices = []
        return count

    def snapshot(self, now_ms=None):
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        self.prune(now_ms)
        output = []
        for device in self.devices:
            item = dict(device)
            for key in ("protocols", "xaddrs", "device_types", "scopes", "source_ips"):
                item[key] = list(device.get(key, []))
            age_ms = max(0, now_ms - item.get("last_seen_ms", now_ms))
            item["age_ms"] = age_ms
            item["presence"] = (
                "online" if age_ms <= self.online_window_ms else "recent"
            )
            if ACTIVE_CAMERA_PROTOCOLS.intersection(item.get("protocols", [])):
                item["classification"] = "camera"
                item["classification_basis"] = "discovery-protocol"
            else:
                # ARP and DHCP establish Layer-2 presence only. They do not
                # prove that a host is a camera.
                item["classification"] = "layer2-candidate"
                item["classification_basis"] = (
                    "arp-dhcp-camera-oui" if item.get("oui_vendor") else
                    "arp-dhcp-only"
                )
            output.append(item)
        output.sort(key=lambda item: _ip_sort_key(item.get("ip", "")))
        return output


def _ip_sort_key(value):
    try:
        return (0, struct.unpack("!I", socket.inet_aton(value))[0])
    except OSError:
        return (1, value or "")


def _warning_once(warnings, message):
    if message not in warnings:
        warnings.append(message)


def _send_round(sockets, payloads, interface, args, warnings):
    sent = 0
    onvif_sock = sockets.get("onvif")
    if onvif_sock is not None:
        try:
            onvif_sock.sendto(payloads["onvif"], (WS_DISCOVERY_GROUP, WS_DISCOVERY_PORT))
            sent += 1
        except OSError as exc:
            _warning_once(warnings, "ONVIF multicast send failed: %s" % exc)

        if not args.no_uniview:
            targets = ["255.255.255.255"]
            directed_broadcast = interface["broadcast"]
            if not args.no_directed_broadcast and directed_broadcast not in targets:
                targets.append(directed_broadcast)
            for target in targets:
                try:
                    onvif_sock.sendto(payloads["uniview"], (target, WS_DISCOVERY_PORT))
                    sent += 1
                except OSError as exc:
                    _warning_once(
                        warnings, "Uniview probe to %s failed: %s" % (target, exc)
                    )

    sadp_sock = sockets.get("sadp")
    if sadp_sock is not None:
        try:
            sadp_sock.sendto(payloads["sadp"], (WS_DISCOVERY_GROUP, SADP_PORT))
            sent += 1
        except OSError as exc:
            _warning_once(warnings, "SADP multicast send failed: %s" % exc)

    sadp6_sock = sockets.get("sadp6")
    if sadp6_sock is not None:
        try:
            interface_index = socket.if_nametoindex(interface["name"])
            sadp6_sock.sendto(
                payloads["sadp"], (SADP6_GROUP, SADP_PORT, 0, interface_index)
            )
            sent += 1
        except (OSError, AttributeError) as exc:
            _warning_once(warnings, "SADP IPv6 multicast send failed: %s" % exc)

    dvrip_sock = sockets.get("dahua-dvrip")
    if dvrip_sock is not None:
        try:
            dvrip_sock.sendto(
                payloads["dahua-dvrip"], ("255.255.255.255", DAHUA_DVRIP_PORT)
            )
            sent += 1
        except OSError as exc:
            _warning_once(warnings, "Dahua DVRIP broadcast send failed: %s" % exc)

    for source_port, destination_port, repeat in DAHUA_DHIP_ENDPOINTS:
        dhip_sock = sockets.get("dahua-dhip-%d" % source_port)
        if dhip_sock is None:
            continue
        for _attempt in range(repeat):
            try:
                dhip_sock.sendto(
                    payloads["dahua-dhip"], (DAHUA_DHIP_GROUP, destination_port)
                )
                sent += 1
            except OSError as exc:
                _warning_once(
                    warnings,
                    "Dahua DHIP probe UDP/%d to UDP/%d failed: %s" %
                    (source_port, destination_port, exc),
                )

    return sent


def _build_result(cache, interface, warnings, stats, baseline=None,
                  started_mono=None, started_wall=None, probe_rounds=0):
    now_ms = int(time.time() * 1000)
    devices = cache.snapshot(now_ms)
    delta = _stats_delta(stats, baseline)
    if started_mono is None:
        duration_ms = 0
    else:
        duration_ms = int((time.monotonic() - started_mono) * 1000)
    if started_wall is None:
        started_wall = now_ms
    online_count = sum(item.get("presence") == "online" for item in devices)
    recent_count = sum(item.get("presence") == "recent" for item in devices)
    camera_count = sum(item.get("classification") == "camera" for item in devices)
    candidate_count = sum(
        item.get("classification") == "layer2-candidate" for item in devices
    )
    oui_match_count = sum(bool(item.get("oui_vendor")) for item in devices)
    return {
        "ok": True,
        "version": VERSION,
        "interface": interface,
        "started_ms": started_wall,
        "finished_ms": now_ms,
        "duration_ms": duration_ms,
        "probe_rounds": probe_rounds,
        "probes_sent": delta["probes_sent"],
        "datagrams_received": delta["datagrams_received"],
        "datagrams_ignored": delta["datagrams_ignored"],
        "arp_packets": delta["arp_packets"],
        "dhcp_packets": delta["dhcp_packets"],
        "warnings": list(dict.fromkeys(warnings)),
        "count": len(devices),
        "online_count": online_count,
        "recent_count": recent_count,
        "camera_count": camera_count,
        "candidate_count": candidate_count,
        "oui_match_count": oui_match_count,
        "cache_size": len(devices),
        "devices": devices,
    }


def run_scan(args):
    interface, warnings, sockets = _open_discovery_sockets(args)
    payloads = _probe_payloads()
    stats = _new_stats()
    cache = DeviceCache(
        args.online_window, args.cache_ttl, args.max_entries,
        oui_db=load_camera_ouis(args.oui_file),
    )

    started_mono = time.monotonic()
    started_wall = int(time.time() * 1000)
    deadline = started_mono + args.timeout
    next_send = started_mono
    rounds_left = args.retries
    fd_to_protocol = {sock.fileno(): name for name, sock in sockets.items()}

    try:
        while True:
            now = time.monotonic()
            if rounds_left > 0 and now >= next_send:
                stats["probes_sent"] += _send_round(
                    sockets, payloads, interface, args, warnings
                )
                rounds_left -= 1
                next_send = now + args.retry_interval
                continue
            if now >= deadline:
                break

            wake_at = min(deadline, next_send) if rounds_left > 0 else deadline
            readable, _, _ = select.select(
                list(sockets.values()), [], [], max(0.0, wake_at - now)
            )
            for sock in readable:
                protocol = fd_to_protocol.get(sock.fileno(), "socket")
                for device in _drain_discovery_socket(
                    sock, protocol, interface, stats, warnings
                ):
                    cache.observe(device)
    finally:
        _close_sockets(sockets)

    return _build_result(
        cache, interface, warnings, stats,
        started_mono=started_mono,
        started_wall=started_wall,
        probe_rounds=args.retries,
    )


def _json_response_bytes(result):
    return (json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _reply_and_close(client, result):
    try:
        client.settimeout(2.0)
        client.sendall(_json_response_bytes(result))
    except OSError:
        pass
    finally:
        try:
            client.close()
        except OSError:
            pass


def _error_result(message):
    return {
        "ok": False,
        "version": VERSION,
        "error": str(message),
        "warnings": [],
        "devices": [],
        "count": 0,
        "online_count": 0,
        "recent_count": 0,
        "camera_count": 0,
        "candidate_count": 0,
        "oui_match_count": 0,
        "cache_size": 0,
    }


def _make_daemon_server(path):
    if os.path.exists(path):
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(0.25)
            probe.connect(path)
        except OSError:
            try:
                os.unlink(path)
            except OSError as exc:
                raise DiscoveryError("cannot remove stale socket %s: %s" % (path, exc))
        else:
            raise DiscoveryError("discovery daemon is already listening on %s" % path)
        finally:
            probe.close()

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_umask = os.umask(0o077)
    try:
        server.bind(path)
    finally:
        os.umask(old_umask)
    os.chmod(path, 0o600)
    server.listen(8)
    server.setblocking(False)
    return server


def run_daemon(args):
    # All sockets, cache mutations, RPC requests, and scan state are owned by
    # this single select loop. The process-wide flock in main() prevents a
    # second scanner/daemon from racing it; no in-process mutex is required.
    interface, warnings, sockets = _open_discovery_sockets(args)
    try:
        server = _make_daemon_server(args.socket_path)
    except Exception:
        _close_sockets(sockets)
        raise
    stats = _new_stats()
    cache = DeviceCache(
        args.online_window, args.cache_ttl, args.max_entries,
        oui_db=load_camera_ouis(args.oui_file),
    )
    fd_to_protocol = {sock.fileno(): name for name, sock in sockets.items()}
    request_clients = {}
    pending_scan_clients = []
    scan_deadline = None
    scan_next_send = None
    scan_rounds_left = 0
    scan_payloads = None
    scan_baseline = None
    scan_started_mono = None
    scan_started_wall = None
    next_periodic = time.monotonic()
    stop_requested = [False]

    def stop_handler(_signum, _frame):
        stop_requested[0] = True

    old_handlers = {}
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        old_handlers[signum] = signal.signal(signum, stop_handler)

    try:
        while not stop_requested[0]:
            now = time.monotonic()
            cache.prune()

            if scan_deadline is not None:
                if scan_rounds_left > 0 and now >= scan_next_send:
                    stats["probes_sent"] += _send_round(
                        sockets, scan_payloads, interface, args, warnings
                    )
                    scan_rounds_left -= 1
                    scan_next_send = now + args.retry_interval
                    continue
                if now >= scan_deadline:
                    result = _build_result(
                        cache, interface, warnings, stats,
                        baseline=scan_baseline,
                        started_mono=scan_started_mono,
                        started_wall=scan_started_wall,
                        probe_rounds=args.retries,
                    )
                    for client in pending_scan_clients:
                        _reply_and_close(client, result)
                    pending_scan_clients = []
                    scan_deadline = None
                    scan_next_send = None
                    scan_payloads = None
                    scan_baseline = None
                    scan_started_mono = None
                    scan_started_wall = None
                    next_periodic = now + args.probe_interval
                    continue
            elif now >= next_periodic:
                payloads = _probe_payloads()
                stats["probes_sent"] += _send_round(
                    sockets, payloads, interface, args, warnings
                )
                next_periodic = now + args.probe_interval

            wake_at = now + 1.0
            if scan_deadline is not None:
                wake_at = min(wake_at, scan_deadline)
                if scan_rounds_left > 0:
                    wake_at = min(wake_at, scan_next_send)
            else:
                wake_at = min(wake_at, next_periodic)

            read_list = list(sockets.values()) + [server] + list(request_clients)
            try:
                readable, _, _ = select.select(
                    read_list, [], [], max(0.0, wake_at - time.monotonic())
                )
            except InterruptedError:
                continue

            for ready in readable:
                if ready is server:
                    for _accept_number in range(MAX_ACCEPT_BATCH):
                        try:
                            client, _ = server.accept()
                        except BlockingIOError:
                            break
                        client.setblocking(False)
                        request_clients[client] = bytearray()
                    continue

                if ready in request_clients:
                    try:
                        chunk = ready.recv(MAX_CLIENT_REQUEST + 1)
                    except BlockingIOError:
                        continue
                    except OSError:
                        chunk = b""
                    if not chunk:
                        request_clients.pop(ready, None)
                        ready.close()
                        continue
                    request_clients[ready].extend(chunk)
                    buffer = request_clients[ready]
                    if len(buffer) > MAX_CLIENT_REQUEST:
                        request_clients.pop(ready, None)
                        _reply_and_close(ready, _error_result("request is too large"))
                        continue
                    if b"\n" not in buffer:
                        continue
                    request_clients.pop(ready, None)
                    raw_request = bytes(buffer).split(b"\n", 1)[0]
                    try:
                        request = json.loads(raw_request.decode("utf-8"))
                        command = request.get("command") if isinstance(request, dict) else None
                    except (UnicodeError, ValueError):
                        command = None

                    if command == "status":
                        result = _build_result(
                            cache, interface, warnings, stats, baseline=stats
                        )
                        _reply_and_close(ready, result)
                    elif command == "clear":
                        cleared = cache.clear()
                        next_periodic = time.monotonic() + args.probe_interval
                        result = _build_result(
                            cache, interface, warnings, stats, baseline=stats
                        )
                        result["cleared"] = cleared
                        _reply_and_close(ready, result)
                    elif command == "scan":
                        pending_scan_clients.append(ready)
                        if scan_deadline is None:
                            scan_started_mono = time.monotonic()
                            scan_started_wall = int(time.time() * 1000)
                            scan_deadline = scan_started_mono + args.scan_wait
                            scan_next_send = scan_started_mono
                            scan_rounds_left = args.retries
                            scan_payloads = _probe_payloads()
                            scan_baseline = dict(stats)
                    else:
                        _reply_and_close(ready, _error_result("unknown daemon command"))
                    continue

                protocol = fd_to_protocol.get(ready.fileno(), "socket")
                for device in _drain_discovery_socket(
                    ready, protocol, interface, stats, warnings
                ):
                    cache.observe(device)
    finally:
        for client in list(request_clients) + pending_scan_clients:
            _reply_and_close(client, _error_result("discovery daemon is stopping"))
        try:
            server.close()
        except OSError:
            pass
        _close_sockets(sockets)
        try:
            os.unlink(args.socket_path)
        except OSError:
            pass
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
    return {"ok": True, "version": VERSION, "stopped": True}


def run_client(args):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(args.client_timeout)
        client.connect(args.socket_path)
        client.sendall(_json_response_bytes({"command": args.client}))
        response = bytearray()
        while b"\n" not in response:
            chunk = client.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > MAX_CLIENT_RESPONSE:
                raise DiscoveryError("daemon response is too large")
    except OSError as exc:
        raise DiscoveryError("cannot query discovery daemon: %s" % exc)
    finally:
        client.close()
    if not response:
        raise DiscoveryError("discovery daemon returned an empty response")
    try:
        return json.loads(bytes(response).split(b"\n", 1)[0].decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise DiscoveryError("discovery daemon returned invalid JSON: %s" % exc)


def _truncate(value, width):
    value = str(value or "-")
    if len(value) <= width:
        return value
    if width <= 1:
        return value[:width]
    return value[:width - 1] + "…"


def _age_text(age_ms):
    try:
        seconds = max(0, int(age_ms) // 1000)
    except (TypeError, ValueError):
        return "-"
    if seconds < 60:
        return "%ds ago" % seconds
    if seconds < 3600:
        return "%dm ago" % (seconds // 60)
    return "%dh ago" % (seconds // 3600)


def _print_table(result):
    interface = result.get("interface") or {}
    print(
        "Interface: %(name)s  IPv4: %(address)s/%(netmask)s  Broadcast: %(broadcast)s" %
        {
            "name": interface.get("name", "-"),
            "address": interface.get("address", "-"),
            "netmask": interface.get("netmask", "-"),
            "broadcast": interface.get("broadcast", "-"),
        }
    )
    if result.get("ok"):
        print(
            "Found %d device(s): %d protocol-confirmed camera(s), %d L2 candidate(s), "
            "%d OUI match(es) "
            "(%d online, %d recent) in %.3f s; "
            "sent %d probe(s), received %d datagram(s)." %
            (
                result.get("count", 0),
                result.get("camera_count", 0),
                result.get("candidate_count", 0),
                result.get("oui_match_count", 0),
                result.get("online_count", 0),
                result.get("recent_count", 0),
                result.get("duration_ms", 0) / 1000.0,
                result.get("probes_sent", 0),
                result.get("datagrams_received", 0),
            )
        )
    else:
        print("Discovery failed: %s" % result.get("error", "unknown error"))

    for warning in result.get("warnings", []):
        print("warning: %s" % warning, file=sys.stderr)

    devices = result.get("devices", [])
    if not devices:
        return

    columns = [
        ("IP", 15),
        ("MAC", 17),
        ("STATE", 7),
        ("CLASS", 13),
        ("LAST SEEN", 12),
        ("PROTOCOL", 24),
        ("VENDOR", 12),
        ("OUI VENDOR", 12),
        ("MODEL / NAME", 24),
        ("SERIAL", 22),
        ("FIRMWARE", 24),
        ("SERVICE", 35),
    ]
    print()
    print("  ".join(title.ljust(width) for title, width in columns))
    print("  ".join("-" * width for _, width in columns))
    for device in devices:
        model_name = device.get("model") or device.get("name")
        if device.get("model") and device.get("name") and device["name"] != device["model"]:
            model_name = "%s / %s" % (device["model"], device["name"])
        service = device.get("web_url")
        if not service and device.get("command_port"):
            service = "command:%s" % device["command_port"]
        values = [
            device.get("ip"),
            device.get("mac"),
            device.get("presence"),
            device.get("classification"),
            _age_text(device.get("age_ms")),
            ",".join(device.get("protocols", [])),
            device.get("manufacturer"),
            device.get("oui_vendor"),
            model_name,
            device.get("serial"),
            device.get("firmware"),
            service,
        ]
        print("  ".join(_truncate(value, width).ljust(width) for value, (_, width) in zip(values, columns)))


def _positive_float(value):
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number")
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def _positive_int(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def build_argument_parser():
    parser = argparse.ArgumentParser(
        description="Discover IP cameras using ONVIF, Uniview, SADP and Dahua UDP probes."
    )
    parser.add_argument("-i", "--interface", help="L3 interface/device, e.g. br-lan or br-camera")
    parser.add_argument("-t", "--timeout", type=_positive_float, default=4.0,
                        help="total receive window in seconds (default: 4.0)")
    parser.add_argument("-r", "--retries", type=_positive_int, default=2,
                        help="number of probe rounds (default: 2)")
    parser.add_argument("--retry-interval", type=_positive_float, default=0.25,
                        help="seconds between probe rounds (default: 0.25)")
    parser.add_argument("--no-onvif", action="store_true",
                        help="disable ONVIF and Uniview WS-Discovery")
    parser.add_argument("--no-uniview", action="store_true",
                        help="disable the Uniview broadcast extension")
    parser.add_argument("--no-sadp", action="store_true",
                        help="disable Hikvision/SADP-style discovery")
    parser.add_argument("--no-dahua", action="store_true",
                        help="disable Dahua DVRIP and DHIP discovery")
    parser.add_argument("--no-directed-broadcast", action="store_true",
                        help="send Uniview only to 255.255.255.255, not the subnet broadcast")
    parser.add_argument("--daemon", action="store_true",
                        help="run the persistent discovery/cache daemon")
    parser.add_argument("--client", choices=("scan", "status", "clear"),
                        help="send a command to the persistent daemon")
    parser.add_argument("--socket", "--socket-path", dest="socket_path",
                        default=DEFAULT_SOCKET_PATH,
                        help="daemon Unix socket path (default: %(default)s)")
    parser.add_argument("--probe-interval", type=_positive_float, default=30.0,
                        help="daemon periodic probe interval (default: 30.0)")
    parser.add_argument("--scan-wait", type=_positive_float, default=5.0,
                        help="daemon immediate-scan receive window (default: 5.0)")
    parser.add_argument("--online-window", type=_positive_float, default=60.0,
                        help="seconds before a cached device becomes recent (default: 60.0)")
    parser.add_argument("--cache-ttl", type=_positive_float, default=300.0,
                        help="seconds before a cached device is removed (default: 300.0)")
    parser.add_argument("--max-entries", type=_positive_int, default=4096,
                        help="maximum cached devices (default: 4096)")
    parser.add_argument("--oui-file", default=DEFAULT_OUI_PATH,
                        help="optional PREFIX|VENDOR OUI overrides (default: %(default)s)")
    parser.add_argument("--client-timeout", type=_positive_float, default=30.0,
                        help="daemon client timeout (default: 30.0)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="list usable IPv4 interfaces and exit")
    parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    return parser


def _emit_result(result, args):
    if args.json:
        print(json.dumps(
            result,
            ensure_ascii=False,
            separators=None if args.pretty else (",", ":"),
            indent=2 if args.pretty else None,
            sort_keys=False,
        ))
    elif args.client == "clear" and result.get("ok"):
        print("Cleared %d cached device(s)." % result.get("cleared", 0))
    else:
        _print_table(result)


def main(argv=None):
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    if args.list_interfaces:
        interfaces = _available_interfaces()
        if args.json:
            print(json.dumps(interfaces, ensure_ascii=False, indent=2 if args.pretty else None))
        else:
            for item in interfaces:
                print("%(name)s\t%(address)s\t%(netmask)s\t%(broadcast)s" % item)
        return 0

    if args.daemon and args.client:
        parser.error("--daemon and --client cannot be used together")
    if args.cache_ttl < args.online_window:
        parser.error("--cache-ttl must be greater than or equal to --online-window")
    if args.no_onvif and args.no_sadp and args.no_dahua:
        parser.error("--no-onvif, --no-sadp and --no-dahua disable every discovery protocol")

    if args.client:
        try:
            result = run_client(args)
        except (DiscoveryError, OSError) as exc:
            result = _error_result(exc)
        _emit_result(result, args)
        return 0 if result.get("ok") else 1

    lock_handle = None
    try:
        lock_handle = _acquire_scan_lock()
        if args.daemon:
            run_daemon(args)
            return 0
        result = run_scan(args)
    except (DiscoveryError, OSError) as exc:
        result = _error_result(exc)
    finally:
        if lock_handle is not None:
            lock_handle.close()

    _emit_result(result, args)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
