"""
Bonus Module — MQTT Topic Enumerator
Connects to open MQTT brokers and subscribes to wildcard topic '#'
to enumerate active topic paths (common in unprotected IoT deployments).

Usage:
    from modules.mqtt_enum import MQTTEnumerator
    topics = MQTTEnumerator(log=log).enumerate("192.168.1.50", 1883)
"""

import socket
import struct
import time
from typing import List


class MQTTEnumerator:
    """
    Lightweight MQTT wildcard subscriber (no external libraries).
    Implements just enough of MQTT 3.1.1 for enumeration.
    """

    def __init__(self, timeout: int = 8, log=None):
        self.timeout = timeout
        self.log     = log

    def enumerate(self, ip: str, port: int = 1883,
                  duration: int = 10) -> List[str]:
        """
        Connect, subscribe to '#', collect topics for `duration` seconds.
        Returns list of unique topic paths.
        """
        topics = set()
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((ip, port))

            # --- CONNECT packet ---
            client_id    = b"iot-sec-scanner"
            payload      = self._encode_str(client_id)
            var_header   = (
                self._encode_str(b"MQTT") +   # Protocol name
                bytes([4]) +                   # Protocol level (3.1.1)
                bytes([0]) +                   # Connect flags (no auth)
                struct.pack(">H", 60)          # Keep-alive 60s
            )
            connect_pkt  = (
                bytes([0x10]) +                # CONNECT
                self._remaining_len(len(var_header) + len(payload)) +
                var_header + payload
            )
            s.sendall(connect_pkt)

            # Read CONNACK
            connack = s.recv(4)
            if len(connack) < 4 or connack[3] != 0:
                self.log and self.log.warn(f"  MQTT {ip}:{port} — CONNACK refused")
                return []
            self.log and self.log.info(f"  MQTT {ip}:{port} — connected (no auth)")

            # --- SUBSCRIBE packet for '#' ---
            msg_id      = 1
            topic_bytes = b"#"
            sub_payload = (
                struct.pack(">H", msg_id) +
                self._encode_str(topic_bytes) +
                bytes([0])                     # QoS 0
            )
            sub_pkt = (
                bytes([0x82]) +
                self._remaining_len(len(sub_payload)) +
                sub_payload
            )
            s.sendall(sub_pkt)
            s.recv(5)  # SUBACK

            # --- Collect PUBLISH messages ---
            s.settimeout(2)
            deadline = time.time() + duration
            while time.time() < deadline:
                try:
                    header = s.recv(1)
                    if not header:
                        break
                    pkt_type = (header[0] >> 4) & 0xF
                    rem_len  = self._read_remaining_len(s)
                    data     = b""
                    while len(data) < rem_len:
                        chunk = s.recv(rem_len - len(data))
                        if not chunk:
                            break
                        data += chunk

                    if pkt_type == 3:   # PUBLISH
                        topic_len = struct.unpack(">H", data[:2])[0]
                        topic     = data[2:2+topic_len].decode("utf-8", errors="replace")
                        topics.add(topic)
                    elif pkt_type == 13: # PINGREQ — send PINGRESP
                        s.sendall(bytes([0xd0, 0x00]))
                except socket.timeout:
                    # Send PINGREQ to keep alive
                    s.settimeout(self.timeout)
                    s.sendall(bytes([0xc0, 0x00]))
                    s.settimeout(2)

            # --- DISCONNECT ---
            s.sendall(bytes([0xe0, 0x00]))
            s.close()

        except ConnectionRefusedError:
            self.log and self.log.warn(f"  MQTT {ip}:{port} — connection refused")
        except Exception as e:
            self.log and self.log.warn(f"  MQTT {ip}:{port} — error: {e}")

        result = sorted(topics)
        if result:
            self.log and self.log.warn(
                f"  MQTT {ip}:{port} — {len(result)} topic(s) found (unauthenticated!)")
        return result

    # ── MQTT encoding helpers ──────────────────────────────────

    def _encode_str(self, s: bytes) -> bytes:
        return struct.pack(">H", len(s)) + s

    def _remaining_len(self, n: int) -> bytes:
        buf = []
        while True:
            enc = n % 128
            n >>= 7
            if n:
                enc |= 0x80
            buf.append(enc)
            if not n:
                break
        return bytes(buf)

    def _read_remaining_len(self, s: socket.socket) -> int:
        mult, val, i = 1, 0, 0
        while True:
            b = s.recv(1)
            if not b:
                return 0
            val  += (b[0] & 127) * mult
            mult *= 128
            if not (b[0] & 128):
                break
            i += 1
            if i > 3:
                break
        return val
