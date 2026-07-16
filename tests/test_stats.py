import time
from types import SimpleNamespace

from ipmonitor.stats import PacketRecord, StatsAggregator


def _geo(country, cc):
    return SimpleNamespace(country=country, country_code=cc)


def test_basic_recording_and_snapshot():
    s = StatsAggregator()
    now = time.time()
    s.record(
        PacketRecord(ts=now, src="1.1.1.1", dst="8.8.8.8",
                     proto="UDP", sport=12345, dport=53, length=120),
        src_geo=_geo("Australia", "AU"),
        dst_geo=_geo("United States", "US"),
    )
    s.record(
        PacketRecord(ts=now + 0.1, src="8.8.8.8", dst="1.1.1.1",
                     proto="UDP", sport=53, dport=12345, length=240),
        src_geo=_geo("United States", "US"),
        dst_geo=_geo("Australia", "AU"),
    )
    snap = s.snapshot()
    assert snap["total_packets"] == 2
    assert snap["total_bytes"] == 360
    assert snap["protocol_counts"]["UDP"] == 2
    assert {c["country_code"] for c in snap["countries"]} == {"AU", "US"}
    us = next(c for c in snap["countries"] if c["country_code"] == "US")
    # 1 inbound (src=US) + 1 outbound (dst=US)
    assert us["packets_in"] == 1
    assert us["packets_out"] == 1
    assert us["bytes_in"] + us["bytes_out"] == 360


def test_rates_nonzero_after_traffic():
    s = StatsAggregator(history_seconds=10)
    now = time.time()
    for i in range(5):
        s.record(
            PacketRecord(ts=now, src="1.2.3.4", dst="5.6.7.8",
                         proto="TCP", sport=1000 + i, dport=443, length=1500),
            src_geo=None, dst_geo=_geo("Germany", "DE"),
        )
    bps, pps = s.rates()
    assert bps > 0
    assert pps > 0


def test_unknown_geo_skipped():
    s = StatsAggregator()
    s.record(
        PacketRecord(ts=time.time(), src="1.1.1.1", dst="2.2.2.2",
                     proto="ICMP", sport=0, dport=0, length=84),
        src_geo=_geo("?", "??"),
        dst_geo=None,
    )
    snap = s.snapshot()
    assert snap["countries"] == []
    assert snap["total_packets"] == 1


def test_hostname_and_process_accounting():
    s = StatsAggregator()
    now = time.time()
    s.record(
        PacketRecord(ts=now, src="1.1.1.1", dst="8.8.8.8",
                     proto="UDP", sport=1000, dport=53, length=200),
        src_geo=None,
        dst_geo=_geo("United States", "US"),
        hostname="google.com",
        process=(4321, "chrome.exe"),
    )
    snap = s.snapshot()
    assert snap["top_hosts"][0] == ("google.com", 200)
    assert "chrome.exe" in snap["top_procs_bytes"][0][0]


def test_continent_aggregation():
    s = StatsAggregator()
    s.record(
        PacketRecord(ts=time.time(), src="1.1.1.1", dst="2.2.2.2",
                     proto="TCP", sport=1, dport=443, length=100),
        src_geo=_geo("Spain", "ES"),
        dst_geo=_geo("United States", "US"),
    )
    snap = s.snapshot()
    conts = {c["continent"] for c in snap["continents"]}
    assert conts == {"EU", "NA"}
