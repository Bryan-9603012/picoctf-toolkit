import math


def continued_fraction(num, den):
    """Generate continued fraction expansion of num/den."""
    while den:
        q = num // den
        r = num % den
        yield q
        num, den = den, r


def convergents(cf):
    """Generate convergents (h/k) from continued fraction expansion."""
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0

    for a in cf:
        h_new = a * h_curr + h_prev
        k_new = a * k_curr + k_prev
        yield h_new, k_new
        h_prev, h_curr = h_curr, h_new
        k_prev, k_curr = k_curr, k_new


def is_perfect_square(n):
    """Check if n is a perfect square, return sqrt if yes, else None."""
    if n < 0:
        return None
    root = int(math.isqrt(n))
    if root * root == n:
        return root
    return None


def wiener_attack(n, e):
    """Attempt Wiener's attack to recover d.

    Returns:
        d if successful, None otherwise.
    """
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue

        # phi = (e*d - 1) / k
        if (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k

        # n = phi + 1 - (p + q)
        # p + q = n - phi + 1
        s = n - phi + 1

        # p and q are roots of x^2 - s*x + n = 0
        discriminant = s * s - 4 * n
        if discriminant < 0:
            continue

        sqrt_disc = is_perfect_square(discriminant)
        if sqrt_disc is None:
            continue

        # p and q
        p = (s + sqrt_disc) // 2
        q = (s - sqrt_disc) // 2

        if p * q == n:
            return d

    return None


def decrypt_rsa(c, d, n):
    """Decrypt ciphertext c using private exponent d.

    Returns:
        Plaintext as integer.
    """
    return pow(c, d, n)


def int_to_text(m):
    """Convert integer plaintext to text string.

    Returns:
        String if conversion successful, None otherwise.
    """
    try:
        hex_str = format(m, 'x')
        if len(hex_str) % 2 == 1:
            hex_str = '0' + hex_str
        bytes_data = bytes.fromhex(hex_str)
        text = bytes_data.decode('utf-8')
        return text
    except:
        return None


def run_wiener_attack(n, e, c):
    """Run Wiener attack on RSA parameters.

    Returns:
        dict with keys: success, d, plaintext, plaintext_int, error
    """
    result = {
        'success': False,
        'd': None,
        'plaintext': None,
        'plaintext_int': None,
        'error': None
    }

    try:
        d = wiener_attack(n, e)

        if d is None:
            result['error'] = 'Wiener attack failed: d not found'
            return result

        result['d'] = d

        m = decrypt_rsa(c, d, n)
        result['plaintext_int'] = m

        text = int_to_text(m)
        if text is not None:
            result['plaintext'] = text
            result['success'] = True
        else:
            # Return hex representation if text conversion fails
            result['plaintext'] = format(m, 'x')
            result['success'] = True

    except Exception as ex:
        result['error'] = str(ex)

    return result
