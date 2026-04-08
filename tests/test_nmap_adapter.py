"""
Deep tests for NmapAdapter and SimplePortScanAdapter.

Covers:
- build_command flag generation for every option combination
- normalize_output XML parser: status, open_ports, services, os
- Schema contract (target, status, open_ports, services, os_detection, error)
- Malformed / empty / partial XML inputs
- Port range logic in SimplePortScanAdapter
"""

from unittest.mock import patch

import pytest

from lattice_mind.adapters.nmap_adapter import NmapAdapter, SimplePortScanAdapter

# ──────────────────────────────────────────────────────────────────────────────
# Sample XML outputs
# ──────────────────────────────────────────────────────────────────────────────

NMAP_XML_BASIC = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0" method="probed"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.18.0" method="probed"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed" reason="reset"/>
        <service name="ssh" method="table"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

NMAP_XML_WITH_OS = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http-alt" product="" version="" method="table"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 4.15" accuracy="95"/>
      <osmatch name="Linux 5.4" accuracy="88"/>
    </os>
  </host>
</nmaprun>"""

NMAP_XML_HOST_DOWN = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports/>
  </host>
</nmaprun>"""

NMAP_XML_NO_HOST = """<?xml version="1.0"?>
<nmaprun/>"""

NMAP_XML_NO_PORTS = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="5.5.5.5" addrtype="ipv4"/>
  </host>
</nmaprun>"""


# ──────────────────────────────────────────────────────────────────────────────
# NmapAdapter.build_command
# ──────────────────────────────────────────────────────────────────────────────


class TestNmapAdapterBuildCommand:

    def setup_method(self):
        self.adapter = NmapAdapter()

    def test_command_starts_with_nmap(self):
        cmd = self.adapter.build_command("192.168.1.0/24", {})
        assert cmd[0] == "nmap"

    def test_default_port_range(self):
        cmd = self.adapter.build_command("192.168.1.1", {})
        assert "-p" in cmd
        assert cmd[cmd.index("-p") + 1] == "1-1000"

    def test_custom_port_range(self):
        cmd = self.adapter.build_command("192.168.1.1", {"ports": "80,443,8080"})
        assert cmd[cmd.index("-p") + 1] == "80,443,8080"

    def test_service_detection_enabled_by_default(self):
        cmd = self.adapter.build_command("192.168.1.1", {})
        assert "-sV" in cmd

    def test_service_detection_disabled(self):
        cmd = self.adapter.build_command("192.168.1.1", {"service_detection": False})
        assert "-sV" not in cmd

    def test_os_detection_disabled_by_default(self):
        cmd = self.adapter.build_command("192.168.1.1", {})
        assert "-O" not in cmd

    def test_os_detection_enabled(self):
        cmd = self.adapter.build_command("192.168.1.1", {"os_detection": True})
        assert "-O" in cmd

    def test_aggressive_disabled_by_default(self):
        cmd = self.adapter.build_command("192.168.1.1", {})
        assert "-A" not in cmd

    def test_aggressive_enabled(self):
        cmd = self.adapter.build_command("192.168.1.1", {"aggressive": True})
        assert "-A" in cmd

    def test_scripts_disabled_by_default(self):
        cmd = self.adapter.build_command("192.168.1.1", {})
        assert "-sC" not in cmd

    def test_scripts_enabled(self):
        cmd = self.adapter.build_command("192.168.1.1", {"scripts": True})
        assert "-sC" in cmd

    def test_xml_output_flags_present(self):
        cmd = self.adapter.build_command("192.168.1.1", {"output_format": "xml"})
        assert "-oX" in cmd
        assert "-" in cmd  # stdout

    def test_target_appended_last(self):
        cmd = self.adapter.build_command("192.168.1.100", {})
        assert cmd[-1] == "192.168.1.100"

    def test_cidr_target(self):
        cmd = self.adapter.build_command("10.0.0.0/24", {})
        assert cmd[-1] == "10.0.0.0/24"

    def test_hostname_target(self):
        cmd = self.adapter.build_command("target.ctf.local", {})
        assert cmd[-1] == "target.ctf.local"


# ──────────────────────────────────────────────────────────────────────────────
# NmapAdapter.normalize_output
# ──────────────────────────────────────────────────────────────────────────────


class TestNmapAdapterNormalizeOutput:

    def setup_method(self):
        self.adapter = NmapAdapter()

    def _assert_schema(self, result):
        for key in (
            "target",
            "status",
            "open_ports",
            "services",
            "os_detection",
            "error",
        ):
            assert key in result, f"Missing key: {key}"
        assert isinstance(result["open_ports"], list)
        assert isinstance(result["services"], dict)
        assert isinstance(result["os_detection"], dict)

    def test_schema_on_valid_xml(self):
        result = self.adapter.normalize_output(NMAP_XML_BASIC)
        self._assert_schema(result)

    def test_host_status_up(self):
        result = self.adapter.normalize_output(NMAP_XML_BASIC)
        assert result["status"] == "up"

    def test_host_status_down(self):
        result = self.adapter.normalize_output(NMAP_XML_HOST_DOWN)
        assert result["status"] == "down"

    def test_target_address_extracted(self):
        result = self.adapter.normalize_output(NMAP_XML_BASIC)
        assert result["target"] == "192.168.1.1"

    def test_open_ports_extracted(self):
        result = self.adapter.normalize_output(NMAP_XML_BASIC)
        assert 80 in result["open_ports"]
        assert 443 in result["open_ports"]

    def test_closed_ports_not_in_open_ports(self):
        result = self.adapter.normalize_output(NMAP_XML_BASIC)
        assert 22 not in result["open_ports"]

    def test_services_dict_populated(self):
        result = self.adapter.normalize_output(NMAP_XML_BASIC)
        assert 80 in result["services"]
        assert result["services"][80]["name"] == "http"

    def test_service_product_and_version(self):
        result = self.adapter.normalize_output(NMAP_XML_BASIC)
        svc = result["services"][80]
        assert svc["product"] == "nginx"
        assert svc["version"] == "1.18.0"

    def test_os_detection_empty_when_absent(self):
        result = self.adapter.normalize_output(NMAP_XML_BASIC)
        assert result["os_detection"] == {}

    def test_os_detection_populated(self):
        result = self.adapter.normalize_output(NMAP_XML_WITH_OS)
        assert len(result["os_detection"]) > 0
        assert "Linux 4.15" in result["os_detection"]

    def test_os_accuracy_stored(self):
        result = self.adapter.normalize_output(NMAP_XML_WITH_OS)
        assert result["os_detection"]["Linux 4.15"]["accuracy"] == "95"

    def test_no_host_in_xml_sets_error(self):
        result = self.adapter.normalize_output(NMAP_XML_NO_HOST)
        self._assert_schema(result)
        assert result["error"] is not None

    def test_empty_ports_gives_empty_open_ports(self):
        result = self.adapter.normalize_output(NMAP_XML_NO_PORTS)
        self._assert_schema(result)
        assert result["open_ports"] == []

    def test_malformed_xml_returns_error(self):
        result = self.adapter.normalize_output("<not valid xml at all <<<")
        self._assert_schema(result)
        assert result["error"] is not None

    def test_empty_string_returns_error(self):
        result = self.adapter.normalize_output("")
        self._assert_schema(result)
        assert result["error"] is not None

    def test_error_is_none_on_success(self):
        result = self.adapter.normalize_output(NMAP_XML_BASIC)
        assert result["error"] is None

    def test_target_10_0_0_1(self):
        result = self.adapter.normalize_output(NMAP_XML_WITH_OS)
        assert result["target"] == "10.0.0.1"

    def test_open_ports_are_integers(self):
        result = self.adapter.normalize_output(NMAP_XML_BASIC)
        for port in result["open_ports"]:
            assert isinstance(port, int)

    def test_services_keyed_by_integer(self):
        result = self.adapter.normalize_output(NMAP_XML_BASIC)
        for port_key in result["services"]:
            assert isinstance(port_key, int)


# ──────────────────────────────────────────────────────────────────────────────
# SimplePortScanAdapter — port range parsing
# ──────────────────────────────────────────────────────────────────────────────


class TestSimplePortScanAdapter:

    def setup_method(self):
        self.adapter = SimplePortScanAdapter()

    def _schema(self, result):
        for k in ("target", "status", "open_ports", "services", "error"):
            assert k in result

    def test_invalid_port_spec_returns_error(self):
        result = self.adapter.run("10.0.0.1", {"ports": "notaport"})
        self._schema(result)
        assert result["error"] is not None

    def test_valid_comma_separated_ports_parsed(self):
        # Mock execute_command to simulate closed ports (no output)
        with patch.object(
            self.adapter, "execute_command", side_effect=RuntimeError("closed")
        ):
            result = self.adapter.run("10.0.0.1", {"ports": "80,443"})
        self._schema(result)
        # All closed, so status should reflect this
        assert result["status"] in ("down", "unknown")

    def test_open_port_detected(self):
        def fake_exec(cmd):
            # Simulate "open" in nc output for port 80
            port = int(cmd[-1])
            if port == 80:
                return "Connection to 10.0.0.1 80 port [tcp/http] succeeded"
            raise RuntimeError("Connection refused")

        with patch.object(self.adapter, "execute_command", side_effect=fake_exec):
            result = self.adapter.run("10.0.0.1", {"ports": "80,443"})
        self._schema(result)
        assert 80 in result["open_ports"]
        assert 443 not in result["open_ports"]

    def test_status_up_when_open_ports_found(self):
        def fake_exec(cmd):
            return "succeeded"

        with patch.object(self.adapter, "execute_command", side_effect=fake_exec):
            result = self.adapter.run("10.0.0.1", {"ports": "80"})
        assert result["status"] == "up"

    def test_status_down_when_no_open_ports(self):
        with patch.object(
            self.adapter, "execute_command", side_effect=RuntimeError("closed")
        ):
            result = self.adapter.run("10.0.0.1", {"ports": "80"})
        assert result["status"] == "down"

    def test_build_command_raises(self):
        with pytest.raises(NotImplementedError):
            self.adapter.build_command("target", {})
