from src.packetlens.analyzer import analyze, entropy, looks_random


def test_random_domain_is_flagged():
    assert looks_random("xk3j9q2z7v1w8.example.net")


def test_normal_domain_is_not_flagged():
    assert not looks_random("example.com")


def test_entropy_of_repeated_text_is_zero():
    assert entropy("aaaa") == 0


def test_analyze_demo_pcap():
    result = analyze("samples/demo.pcap")
    assert result["total"] == 3
    assert result["protocols"]["UDP"] == 2
    assert len(result["suspicious_dns"]) == 1