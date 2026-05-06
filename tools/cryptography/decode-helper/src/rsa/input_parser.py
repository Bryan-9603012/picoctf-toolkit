import re


def parse_rsa_file(filepath):
    """Parse RSA parameters from a file.

    Expected format:
        n = 12345...
        e = 65537...
        c = 67890...

    Returns:
        dict with keys: n, e, c (all as integers)
    """
    params = {}
    patterns = {
        'n': re.compile(r'n\s*=\s*(\d+)'),
        'e': re.compile(r'e\s*=\s*(\d+)'),
        'c': re.compile(r'c\s*=\s*(\d+)'),
    }

    with open(filepath, 'r') as f:
        content = f.read()

    for key, pattern in patterns.items():
        match = pattern.search(content)
        if match:
            params[key] = int(match.group(1))

    return params


def parse_rsa_cli(n_str, e_str, c_str):
    """Parse RSA parameters from CLI arguments.

    Returns:
        dict with keys: n, e, c (all as integers)
    """
    params = {}
    if n_str:
        params['n'] = int(n_str)
    if e_str:
        params['e'] = int(e_str)
    if c_str:
        params['c'] = int(c_str)
    return params


def validate_rsa_params(params):
    """Validate that all required RSA parameters are present.

    Returns:
        (is_valid, error_message)
    """
    required = ['n', 'e', 'c']
    missing = [k for k in required if k not in params]
    if missing:
        return False, f"Missing required parameters: {', '.join(missing)}"
    return True, None
