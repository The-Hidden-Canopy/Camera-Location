import os
import shutil
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("CAM_SECRET_BACKEND", "plain")
os.environ.setdefault("CAM_SECRET_DIR", str(ROOT / "tests" / "unit" / "persistence" / "_test_secrets"))

import camdiscover.discovery as discovery
from camdiscover.discovery import OnvifDeviceAudit, query_onvif_device_audit, query_onvif_device_info
from camdiscover.webapp import create_app


def _workspace_temp_dir() -> Path:
    path = ROOT / ".pytest_cache" / "onvif-audit" / str(uuid.uuid4())
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_onvif_audit_collects_odm_style_capabilities(monkeypatch):
    def fake_soap(url: str, username: str, password: str, body_xml: str, timeout: float = 5.0) -> str:
        if "GetDeviceInformation" in body_xml:
            return """
                <tds:GetDeviceInformationResponse>
                  <tds:Manufacturer>Hikvision</tds:Manufacturer>
                  <tds:Model>DS-2CD2347G2-LU</tds:Model>
                  <tds:FirmwareVersion>V5.7.11</tds:FirmwareVersion>
                  <tds:SerialNumber>SN-ONVIF-1</tds:SerialNumber>
                  <tds:HardwareId>HW-77</tds:HardwareId>
                </tds:GetDeviceInformationResponse>
            """
        if "GetServices" in body_xml:
            return """
                <tds:GetServicesResponse>
                  <tds:Service><tds:Namespace>http://www.onvif.org/ver10/device/wsdl</tds:Namespace><tds:XAddr>http://192.168.88.42/onvif/device_service</tds:XAddr></tds:Service>
                  <tds:Service><tds:Namespace>http://www.onvif.org/ver10/media/wsdl</tds:Namespace><tds:XAddr>http://192.168.88.42/onvif/media_service</tds:XAddr></tds:Service>
                  <tds:Service><tds:Namespace>http://www.onvif.org/ver20/imaging/wsdl</tds:Namespace><tds:XAddr>http://192.168.88.42/onvif/imaging_service</tds:XAddr></tds:Service>
                  <tds:Service><tds:Namespace>http://www.onvif.org/ver20/ptz/wsdl</tds:Namespace><tds:XAddr>http://192.168.88.42/onvif/ptz_service</tds:XAddr></tds:Service>
                  <tds:Service><tds:Namespace>http://www.onvif.org/ver10/events/wsdl</tds:Namespace><tds:XAddr>http://192.168.88.42/onvif/events_service</tds:XAddr></tds:Service>
                </tds:GetServicesResponse>
            """
        if "GetCapabilities" in body_xml:
            return """
                <tds:GetCapabilitiesResponse>
                  <tds:Capabilities>
                    <tt:Device><tt:XAddr>http://192.168.88.42/onvif/device_service</tt:XAddr></tt:Device>
                    <tt:Media><tt:XAddr>http://192.168.88.42/onvif/media_service</tt:XAddr></tt:Media>
                    <tt:Imaging><tt:XAddr>http://192.168.88.42/onvif/imaging_service</tt:XAddr></tt:Imaging>
                    <tt:PTZ><tt:XAddr>http://192.168.88.42/onvif/ptz_service</tt:XAddr></tt:PTZ>
                    <tt:Events><tt:XAddr>http://192.168.88.42/onvif/events_service</tt:XAddr></tt:Events>
                  </tds:Capabilities>
                </tds:GetCapabilitiesResponse>
            """
        if "GetScopes" in body_xml:
            return """
                <tds:GetScopesResponse>
                  <tds:Scopes><tt:ScopeItem>onvif://www.onvif.org/type/NetworkVideoTransmitter</tt:ScopeItem></tds:Scopes>
                  <tds:Scopes><tt:ScopeItem>onvif://www.onvif.org/name/North%20Gate</tt:ScopeItem></tds:Scopes>
                </tds:GetScopesResponse>
            """
        if "GetNetworkInterfaces" in body_xml:
            return """
                <tds:GetNetworkInterfacesResponse>
                  <tds:NetworkInterfaces>
                    <tt:IPv4><tt:Config><tt:Manual><tt:Address>192.168.88.42</tt:Address></tt:Manual></tt:Config></tt:IPv4>
                    <tt:IPv4Address>192.168.88.42</tt:IPv4Address>
                  </tds:NetworkInterfaces>
                </tds:GetNetworkInterfacesResponse>
            """
        if "GetNetworkDefaultGateway" in body_xml:
            return "<tds:GetNetworkDefaultGatewayResponse><tt:IPv4Address>192.168.88.1</tt:IPv4Address></tds:GetNetworkDefaultGatewayResponse>"
        if "GetDNS" in body_xml:
            return """
                <tds:GetDNSResponse>
                  <tt:IPv4Address>8.8.8.8</tt:IPv4Address>
                  <tt:IPv4Address>1.1.1.1</tt:IPv4Address>
                </tds:GetDNSResponse>
            """
        if "GetNTP" in body_xml:
            return "<tds:GetNTPResponse><tt:IPv4Address>192.168.88.1</tt:IPv4Address></tds:GetNTPResponse>"
        if "GetSystemDateAndTime" in body_xml:
            return """
                <tds:GetSystemDateAndTimeResponse>
                  <tt:UTCDateTime>
                    <tt:Time><tt:Hour>14</tt:Hour><tt:Minute>05</tt:Minute><tt:Second>33</tt:Second></tt:Time>
                    <tt:Date><tt:Year>2026</tt:Year><tt:Month>7</tt:Month><tt:Day>16</tt:Day></tt:Date>
                  </tt:UTCDateTime>
                </tds:GetSystemDateAndTimeResponse>
            """
        if "GetUsers" in body_xml:
            return "<tds:GetUsersResponse><tds:User/><tds:User/></tds:GetUsersResponse>"
        if "GetProfiles" in body_xml:
            return """
                <trt:GetProfilesResponse>
                  <trt:Profiles token="Profile_1">
                    <tt:VideoSourceConfiguration token="VideoSource_1" />
                  </trt:Profiles>
                  <trt:Profiles token="Profile_2">
                    <tt:VideoSourceConfiguration token="VideoSource_2" />
                  </trt:Profiles>
                </trt:GetProfilesResponse>
            """
        if "GetStreamUri" in body_xml and "Profile_1" in body_xml:
            return "<trt:GetStreamUriResponse><tt:Uri>rtsp://192.168.88.42/Streaming/Channels/101</tt:Uri></trt:GetStreamUriResponse>"
        if "GetStreamUri" in body_xml and "Profile_2" in body_xml:
            return "<trt:GetStreamUriResponse><tt:Uri>rtsp://192.168.88.42/Streaming/Channels/102</tt:Uri></trt:GetStreamUriResponse>"
        if "GetSnapshotUri" in body_xml and "Profile_1" in body_xml:
            return "<trt:GetSnapshotUriResponse><tt:Uri>http://192.168.88.42/ISAPI/Streaming/channels/101/picture</tt:Uri></trt:GetSnapshotUriResponse>"
        if "GetSnapshotUri" in body_xml and "Profile_2" in body_xml:
            return "<trt:GetSnapshotUriResponse><tt:Uri>http://192.168.88.42/ISAPI/Streaming/channels/102/picture</tt:Uri></trt:GetSnapshotUriResponse>"
        if "GetVideoEncoderConfigurations" in body_xml:
            return "<trt:GetVideoEncoderConfigurationsResponse><trt:Configurations /></trt:GetVideoEncoderConfigurationsResponse>"
        if "GetConfigurations" in body_xml:
            return "<tptz:GetConfigurationsResponse><tptz:PTZConfiguration /></tptz:GetConfigurationsResponse>"
        if "GetImagingSettings" in body_xml:
            return "<timg:GetImagingSettingsResponse><tt:Brightness>50</tt:Brightness></timg:GetImagingSettingsResponse>"
        if "GetEventProperties" in body_xml:
            return "<tev:GetEventPropertiesResponse><tev:TopicSet /></tev:GetEventPropertiesResponse>"
        raise AssertionError(f"unexpected SOAP body: {body_xml}")

    monkeypatch.setattr(discovery, "_onvif_soap", fake_soap)

    audit = query_onvif_device_audit("192.168.88.42", "http://192.168.88.42/onvif/device_service")

    assert audit.manufacturer == "Hikvision"
    assert audit.model == "DS-2CD2347G2-LU"
    assert audit.serial == "SN-ONVIF-1"
    assert audit.hardware_id == "HW-77"
    assert audit.stream_uris == [
        "rtsp://192.168.88.42/Streaming/Channels/101",
        "rtsp://192.168.88.42/Streaming/Channels/102",
    ]
    assert audit.snapshot_uris == [
        "http://192.168.88.42/ISAPI/Streaming/channels/101/picture",
        "http://192.168.88.42/ISAPI/Streaming/channels/102/picture",
    ]
    assert audit.scopes == [
        "onvif://www.onvif.org/type/NetworkVideoTransmitter",
        "onvif://www.onvif.org/name/North%20Gate",
    ]
    assert set(audit.services) >= {"device", "media", "imaging", "ptz", "events"}
    assert set(audit.capabilities) >= {"device", "media", "imaging", "ptz", "events"}
    assert audit.media_profile_tokens == ["Profile_1", "Profile_2"]
    assert audit.reported_ipv4_addresses == ["192.168.88.42"]
    assert audit.default_gateways == ["192.168.88.1"]
    assert audit.dns_servers == ["8.8.8.8", "1.1.1.1"]
    assert audit.ntp_servers == ["192.168.88.1"]
    assert audit.system_datetime == "2026-07-16T14:05:33"
    assert audit.user_count == 2
    assert audit.supports_device is True
    assert audit.supports_media is True
    assert audit.supports_events is True
    assert audit.supports_imaging is True
    assert audit.supports_ptz is True
    assert audit.checks["get_device_information"] is True
    assert audit.checks["get_profiles"] is True
    assert audit.checks["get_event_properties"] is True

    info = query_onvif_device_info("192.168.88.42", "http://192.168.88.42/onvif/device_service")
    assert info.manufacturer == audit.manufacturer
    assert info.stream_uris == audit.stream_uris


def test_onvif_audit_surfaces_primary_error(monkeypatch):
    def failing_soap(url: str, username: str, password: str, body_xml: str, timeout: float = 5.0) -> str:
        raise OSError("camera did not respond")

    monkeypatch.setattr(discovery, "_onvif_soap", failing_soap)

    audit = query_onvif_device_audit("192.168.88.99")
    assert audit.error == "camera did not respond"
    assert audit.checks["get_device_information"] is False

    info = query_onvif_device_info("192.168.88.99")
    assert info.error == "camera did not respond"


def test_onvif_info_route_returns_richer_audit_payload(monkeypatch):
    temp_dir = _workspace_temp_dir()
    try:
        app = create_app(db_path=str(temp_dir / "onvif.db"))

        def fake_audit(ip: str, onvif_url: str = "", username: str = "admin", password: str = "") -> OnvifDeviceAudit:
            return OnvifDeviceAudit(
                manufacturer="Hikvision",
                model="DS-2CD2347G2-LU",
                firmware="V5.7.11",
                serial="SN-ROUTE-1",
                hardware_id="HW-ROUTE",
                stream_uris=["rtsp://192.168.88.42/Streaming/Channels/101"],
                snapshot_uris=["http://192.168.88.42/picture"],
                scopes=["onvif://www.onvif.org/type/NetworkVideoTransmitter"],
                services=["device", "media", "events"],
                capabilities=["device", "media", "events"],
                media_profile_tokens=["Profile_1"],
                service_urls={"media": "http://192.168.88.42/onvif/media_service"},
                reported_ipv4_addresses=["192.168.88.42"],
                default_gateways=["192.168.88.1"],
                dns_servers=["8.8.8.8"],
                ntp_servers=["192.168.88.1"],
                system_datetime="2026-07-16T14:05:33",
                user_count=2,
                supports_device=True,
                supports_media=True,
                supports_events=True,
                checks={"get_device_information": True, "get_profiles": True},
            )

        monkeypatch.setattr(discovery, "query_onvif_device_audit", fake_audit)

        client = app.test_client()
        resp = client.get("/api/devices/192.168.88.42/onvif-info?user=admin&pass=secret")
        body = resp.get_json()

        assert resp.status_code == 200
        assert body["manufacturer"] == "Hikvision"
        assert body["stream_uris"] == ["rtsp://192.168.88.42/Streaming/Channels/101"]
        assert body["snapshot_uris"] == ["http://192.168.88.42/picture"]
        assert body["services"] == ["device", "media", "events"]
        assert body["reported_ipv4_addresses"] == ["192.168.88.42"]
        assert body["default_gateways"] == ["192.168.88.1"]
        assert body["checks"]["get_profiles"] is True
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
