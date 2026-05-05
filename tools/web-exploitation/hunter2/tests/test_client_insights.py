from types import SimpleNamespace

from scanning.passive.client_insights import analyze_response, analyze_script_response


class HeaderDict(dict):
    def get_all(self, key):
        v = self.get(key)
        if not v:
            return []
        return [v]


class FakeResp:
    def __init__(self, text, headers=None, status_code=200, url='http://example.com/'):
        self.text = text
        self.content = text.encode()
        self.headers = HeaderDict(headers or {"Content-Type": "text/html"})
        self.status_code = status_code
        self.url = url
        self._hunter_elapsed_ms = 5


def test_detects_hidden_html_comment_flag():
    resp = FakeResp('<html><!--picoCTF{abc}--></html>')
    result = analyze_response('http://example.com/', resp, resp.text)
    ids = [f.rule_id for f in result.findings]
    assert 'passive-html-comment-clue' in ids


def test_detects_cookie_clue_and_missing_expiry():
    resp = FakeResp('<html>ok</html>', headers={
        'Content-Type': 'text/html',
        'Set-Cookie': 'session=admin; Path=/; HttpOnly'
    })
    result = analyze_response('http://example.com/', resp, resp.text)
    ids = [f.rule_id for f in result.findings]
    assert 'passive-cookie-clue' in ids
    assert 'passive-session-missing-expiry' in ids


def test_detects_javascript_uri_and_auth_logic():
    body = '''
    <a href="javascript:alert(1)">x</a>
    <script>if (role == "admin") { console.log("ok") }</script>
    '''
    resp = FakeResp(body)
    result = analyze_response('http://example.com/', resp, body)
    ids = [f.rule_id for f in result.findings]
    assert 'passive-bookmarklet-uri' in ids
    assert 'passive-client-auth-logic' in ids


def test_detects_script_encoded_clue():
    text = 'const msg = "cGljb0NURnt0ZXN0fQ==";'
    resp = FakeResp(text, headers={'Content-Type': 'application/javascript'})
    findings = analyze_script_response('http://example.com/app.js', resp, text)
    assert any(f.rule_id == 'passive-script-encoded-clue' for f in findings)
