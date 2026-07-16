import time
from types import SimpleNamespace

from ipmonitor.alerts import AlertEngine
from ipmonitor.stats import PacketRecord


def _pkt(src="1.1.1.1", dst="8.8.8.8", dport=443):
    return PacketRecord(
        ts=time.time(), src=src, dst=dst, proto="TCP",
        sport=44444, dport=dport, length=1000,
    )


def _geo(country, cc):
    return SimpleNamespace(country=country, country_code=cc)


def test_block_country_triggers_crit():
    a = AlertEngine(block_countries=["RU"], notify_new_country=False)
    a.evaluate_packet(_pkt(), _geo("Russia", "RU"), None)
    all_ = a.all()
    assert any(x.rule == "block_country" and x.severity == "crit" for x in all_)


def test_block_port_triggers_warn():
    a = AlertEngine(block_ports=[23], notify_new_country=False)
    a.evaluate_packet(_pkt(dport=23), None, _geo("Elbonia", "XX"))
    assert any(x.rule == "block_port" and x.severity == "warn" for x in a.all())


def test_new_country_alert():
    a = AlertEngine()
    a.evaluate_packet(_pkt(), _geo("Spain", "ES"), _geo("US", "US"))
    a.evaluate_packet(_pkt(), _geo("Spain", "ES"), _geo("US", "US"))
    news = [x for x in a.all() if x.rule == "new_country"]
    assert len(news) == 2  # ES + US, once each


def test_rate_spike():
    a = AlertEngine(rate_bytes_per_sec=1000)
    a.evaluate_rate(500)
    a.evaluate_rate(50_000)
    assert any(x.rule == "rate_spike" for x in a.all())


def test_dedup_within_window():
    a = AlertEngine(block_countries=["RU"], notify_new_country=False)
    for _ in range(5):
        a.evaluate_packet(_pkt(), _geo("Russia", "RU"), None)
    assert sum(1 for x in a.all() if x.rule == "block_country") == 1
