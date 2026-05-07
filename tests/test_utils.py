from ipmonitor.utils import (
    country_flag,
    format_bytes,
    format_rate,
    is_private_ip,
    service_name,
)


def test_is_private_ip_v4():
    assert is_private_ip("10.0.0.1")
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("172.16.0.5")
    assert is_private_ip("127.0.0.1")
    assert is_private_ip("169.254.10.1")
    assert not is_private_ip("8.8.8.8")
    assert not is_private_ip("1.1.1.1")


def test_is_private_ip_v6():
    assert is_private_ip("::1")
    assert is_private_ip("fe80::1")
    assert is_private_ip("fc00::1")
    assert not is_private_ip("2606:4700:4700::1111")


def test_is_private_ip_invalid():
    assert is_private_ip("")
    assert is_private_ip("not-an-ip")


def test_format_bytes():
    assert format_bytes(0) == "0.0 B"
    assert format_bytes(1023).endswith("B")
    assert format_bytes(1024).endswith("KB")
    assert format_bytes(1024 * 1024).endswith("MB")
    assert format_bytes(1024 ** 3).endswith("GB")


def test_format_rate():
    assert format_rate(2048).endswith("/s")


def test_country_flag():
    assert country_flag("ES") == "\U0001F1EA\U0001F1F8"
    assert country_flag("US") == "\U0001F1FA\U0001F1F8"
    assert country_flag("??") != ""
    assert country_flag(None) != ""
    assert country_flag("X") != ""


def test_service_name():
    assert service_name(443) == "https"
    assert service_name(53) == "dns"
    assert service_name(0) == "-"
    assert service_name(99999) == ""
