from ipmonitor.dpi import _parse_http_host, _parse_tls_sni


def test_http_host_extraction():
    req = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: test\r\n\r\n"
    )
    assert _parse_http_host(req) == "example.com"


def test_http_host_missing():
    req = b"GET / HTTP/1.1\r\n\r\n"
    assert _parse_http_host(req) == ""


def test_http_host_wrong_start():
    assert _parse_http_host(b"HELLO WORLD") == ""


def test_tls_sni_extraction():
    # Minimal handcrafted ClientHello with SNI "example.org".
    # Bytes:
    # 16 03 01 LL LL                  TLS record: Handshake, TLS1.0
    # 01 00 00 LL                     Handshake: ClientHello, length
    # 03 03                           client_version TLS1.2
    # <32 bytes random>
    # 00                              session_id length = 0
    # 00 02 00 2f                     cipher_suites: 1 suite (len=2), 0x002f
    # 01 00                           compression: 1 method, null
    # 00 15                           extensions total length = 21
    # 00 00 00 11                     extension type=server_name, length=17
    # 00 0f                           server_name_list length=15
    # 00                              name_type = host_name
    # 00 0b                           name length = 11
    # "example.org"                   the SNI
    body = bytearray()
    body += b"\x03\x03"
    body += b"\x00" * 32
    body += b"\x00"
    body += b"\x00\x02\x00\x2f"
    body += b"\x01\x00"
    ext = bytearray()
    sni_ext_val = b"\x00\x0f\x00\x00\x0b" + b"example.org"
    ext += b"\x00\x00" + len(sni_ext_val).to_bytes(2, "big") + sni_ext_val
    body += len(ext).to_bytes(2, "big") + ext

    handshake = b"\x01" + len(body).to_bytes(3, "big") + bytes(body)
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake

    assert _parse_tls_sni(record) == "example.org"


def test_tls_sni_malformed():
    assert _parse_tls_sni(b"") == ""
    assert _parse_tls_sni(b"\x14\x03\x01") == ""
    assert _parse_tls_sni(b"\x16\x03\x01\x00\x05\x02\x00\x00\x00") == ""
