from ipmonitor.continents import continent_for
from ipmonitor.hosts import HostRegistry
from ipmonitor.sparkline import sparkline


def test_continent_lookup():
    cc, name, emoji = continent_for("ES")
    assert cc == "EU"
    assert "Europe" in name
    cc, _, _ = continent_for("US")
    assert cc == "NA"
    cc, _, _ = continent_for("BR")
    assert cc == "SA"
    cc, _, _ = continent_for("ZZ")
    assert cc == "??"
    cc, _, _ = continent_for(None)
    assert cc == "??"


def test_sparkline_basic():
    s = sparkline([0, 1, 2, 3, 4], width=5)
    assert len(s) == 5
    # empty
    assert sparkline([], width=4) == "····"
    # all zeros
    assert set(sparkline([0, 0, 0], width=3)) == {"▁"}


def test_host_registry_ranking():
    r = HostRegistry(reverse_dns=False)
    r.observe_http("1.2.3.4", "http-host.example")
    r.observe_sni("1.2.3.4", "sni.example")
    r.observe_dns("dns.example", "1.2.3.4")
    # dns beats sni beats http
    assert r.get("1.2.3.4") == "dns.example"
    all_ = r.all_for("1.2.3.4")
    assert all_[0] == "dns.example"


def test_host_registry_accounting():
    r = HostRegistry(reverse_dns=False)
    r.account("example.com", 500)
    r.account("example.com", 700)
    r.account("other.example", 200)
    top = r.top_hostnames()
    assert top[0]["host"] == "example.com"
    assert top[0]["bytes"] == 1200
