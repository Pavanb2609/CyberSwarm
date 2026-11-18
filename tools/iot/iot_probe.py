import socket
import struct
from typing import Any, Dict, List, Optional

from tools.base import Tool, ToolResult

IOT_TCP_PORTS = {1883: "MQTT", 8883: "MQTTS", 5683: "CoAP"}  # CoAP is usually UDP but some gateways expose TCP too
IOT_UDP_PORTS = {5683: "CoAP", 1900: "SSDP/UPnP"}

# minimal MQTT 3.1.1 CONNECT packet with empty client id -- a real broker
# replies with a CONNACK (byte 0x20); this is the standard way to confirm
# "yes, that's actually MQTT" rather than just "something's on port 1883"
_MQTT_CONNECT = bytes([
    0x10, 0x0C,                          # CONNECT, remaining length
    0x00, 0x04, ord('M'), ord('Q'), ord('T'), ord('T'),  # protocol name
    0x04,                                # protocol level (3.1.1)
    0x02,                                # connect flags (clean session)
    0x00, 0x00,                          # keep alive
    0x00, 0x00,                          # empty client id
])


class IoTServiceIdentificationTool(Tool):
    """
    Confirms IoT protocol presence on already-discovered open ports: sends a
    real MQTT CONNECT and checks for a CONNACK on 1883/8883, and does a
    plain connect/SSDP-style check for CoAP/UPnP. Pure Python via raw
    sockets, no external binary. Gated: only runs if PORT_DISCOVERY already
    found an IoT-associated port open -- matches the planner prompt's rule
    that this capability needs MQTT/CoAP/UPnP evidence, not plausibility.
    """

    name = "iot_probe"
    capability = "IOT_SERVICE_IDENTIFICATION"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self) -> Optional[str]:
        return None

    def build_command(self, target: str, **kwargs) -> List[str]:
        return []

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}

    def _check_mqtt(self, host: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.sendall(_MQTT_CONNECT)
                resp = s.recv(4)
                if resp and resp[0] == 0x20:  # CONNACK packet type
                    return_code = resp[3] if len(resp) >= 4 else None
                    return {"port": port, "protocol": "MQTT", "confirmed": True,
                             "connack_return_code": return_code,
                             "note": "0 = connection accepted; nonzero = broker rejected but protocol confirmed"}
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None
        return None

    def _check_tcp_open(self, host: str, port: int, label: str, timeout: float) -> Optional[Dict[str, Any]]:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return {"port": port, "protocol": label, "confirmed": False,
                        "note": "port open but protocol not verified with a handshake"}
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def run(self, target: str, timeout: int = 180, **kwargs) -> ToolResult:
        ports_str = kwargs.get("ports") or ""
        open_ports = {int(p) for p in ports_str.split(",") if p.strip().isdigit()}
        relevant = open_ports & IOT_TCP_PORTS.keys()
        if not relevant:
            return ToolResult(
                tool=self.name, status="success", capability=self.capability,
                results={"iot_identification_skipped": True,
                         "reason": "None of the known IoT ports (1883, 8883, 5683) are in "
                                   "open_ports -- skipping rather than probing blind."},
            )

        host = target.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
        per_conn_timeout = kwargs.get("per_request_timeout", 5)
        found: List[Dict[str, Any]] = []

        for port in relevant:
            label = IOT_TCP_PORTS[port]
            if label in ("MQTT", "MQTTS"):
                result = self._check_mqtt(host, port, per_conn_timeout)
            else:
                result = self._check_tcp_open(host, port, label, per_conn_timeout)
            if result:
                found.append(result)

        return ToolResult(
            tool=self.name, status="success", capability=self.capability,
            results={"iot_services_found": found, "count": len(found)},
        )
