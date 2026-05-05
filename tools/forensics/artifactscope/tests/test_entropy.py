from artifactscope.entropy import classify_entropy, shannon_entropy


def test_entropy_empty():
    assert shannon_entropy(b"") == 0.0


def test_entropy_low():
    score = shannon_entropy(b"A" * 100)
    assert score < 1.0
    assert classify_entropy(score) == "low"
