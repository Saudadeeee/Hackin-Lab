<?php
/**
 * JWT Lab · minimal JWT implementation
 * ---------------------------------------------------------------------------
 * Hand-rolled on purpose. Every level reuses these primitives and then adds
 * its own (broken) verification logic on top, so the learner can see exactly
 * which step of the standard flow the level skipped.
 *
 * A correct JWT verification does all of this, in this order:
 *   1. split the compact serialisation into header / payload / signature
 *   2. decide the algorithm from SERVER policy, never from the token header
 *   3. resolve the key for that algorithm from a trusted key store
 *   4. verify the signature over "header.payload" with a constant-time compare
 *   5. only then parse claims, and validate exp / nbf / iss / aud
 *   6. only then read authorisation claims
 * Each level in this lab removes or corrupts exactly one of these steps.
 */

/* ------------------------------------------------------------------ base64url */

function jwt_b64url_encode(string $bin): string
{
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

function jwt_b64url_decode(string $txt): string
{
    $txt = strtr($txt, '-_', '+/');
    $pad = strlen($txt) % 4;
    if ($pad) {
        $txt .= str_repeat('=', 4 - $pad);
    }
    return (string)base64_decode($txt, false);
}

/* ------------------------------------------------------------------ structure */

/** @return array{0:string,1:string,2:string}|null raw base64url segments */
function jwt_split(string $token): ?array
{
    $parts = explode('.', trim($token));
    if (count($parts) !== 3) {
        return null;
    }
    return [$parts[0], $parts[1], $parts[2]];
}

function jwt_header_raw(string $token): string
{
    $p = jwt_split($token);
    return $p ? jwt_b64url_decode($p[0]) : '';
}

function jwt_payload_raw(string $token): string
{
    $p = jwt_split($token);
    return $p ? jwt_b64url_decode($p[1]) : '';
}

function jwt_header(string $token): ?array
{
    $d = json_decode(jwt_header_raw($token), true);
    return is_array($d) ? $d : null;
}

/** Decode claims WITHOUT verifying anything. Named to make the danger obvious. */
function jwt_claims_unverified(string $token): ?array
{
    $d = json_decode(jwt_payload_raw($token), true);
    return is_array($d) ? $d : null;
}

function jwt_signing_input(string $token): string
{
    $p = jwt_split($token);
    return $p ? $p[0] . '.' . $p[1] : '';
}

function jwt_signature(string $token): string
{
    $p = jwt_split($token);
    return $p ? jwt_b64url_decode($p[2]) : '';
}

/* ------------------------------------------------------------------ signing */

function jwt_encode(array $header, array $claims, string $key): string
{
    $h   = jwt_b64url_encode(json_encode($header, JSON_UNESCAPED_SLASHES));
    $p   = jwt_b64url_encode(json_encode($claims, JSON_UNESCAPED_SLASHES));
    $in  = $h . '.' . $p;
    $alg = strtoupper($header['alg'] ?? 'HS256');

    if ($alg === 'NONE') {
        return $in . '.';
    }
    if ($alg === 'RS256') {
        $sig = '';
        openssl_sign($in, $sig, $key, OPENSSL_ALGO_SHA256);
        return $in . '.' . jwt_b64url_encode($sig);
    }
    // HS256 default
    return $in . '.' . jwt_b64url_encode(hash_hmac('sha256', $in, $key, true));
}

function jwt_sign_hs256(string $signingInput, string $secret): string
{
    return jwt_b64url_encode(hash_hmac('sha256', $signingInput, $secret, true));
}

function jwt_verify_hs256(string $token, string $secret): bool
{
    $p = jwt_split($token);
    if (!$p) {
        return false;
    }
    return hash_equals(jwt_sign_hs256($p[0] . '.' . $p[1], $secret), $p[2]);
}

function jwt_verify_rs256(string $token, string $publicPem): bool
{
    $p = jwt_split($token);
    if (!$p) {
        return false;
    }
    $res = openssl_verify($p[0] . '.' . $p[1], jwt_b64url_decode($p[2]), $publicPem, OPENSSL_ALGO_SHA256);
    return $res === 1;
}

/* ------------------------------------------------------------------ key store */

function jwt_keys_dir(): string
{
    return __DIR__ . '/keys';
}

function jwt_private_key(): string
{
    return (string)@file_get_contents(jwt_keys_dir() . '/private.pem');
}

function jwt_public_key(): string
{
    return (string)@file_get_contents(jwt_keys_dir() . '/public.pem');
}

/** The HS256 secret the lab's "production" issuer uses. Strong on purpose. */
function jwt_strong_secret(): string
{
    return 'c8b1f0d47e2a4a5b9c3e6f81d0a7b264f95c3e18aa7d4b60e21c9f3a5d7b8e40';
}

/**
 * Build the token the lab hands you at the start of a level.
 * Always a low-privilege user; forging privilege is the whole exercise.
 */
function jwt_issue_guest(string $alg = 'HS256', string $key = '', array $extraHeader = [], array $extraClaims = []): string
{
    $header = array_merge(['typ' => 'JWT', 'alg' => $alg], $extraHeader);
    $claims = array_merge([
        'sub'  => 'guest',
        'name' => 'Guest User',
        'role' => 'user',
        'iss'  => 'https://auth.hackinlab.internal',
        'iat'  => time(),
        'exp'  => time() + 3600,
    ], $extraClaims);

    if ($key === '') {
        $key = $alg === 'RS256' ? jwt_private_key() : jwt_strong_secret();
    }
    return jwt_encode($header, $claims, $key);
}

/* ------------------------------------------------------------------ display */

/** Pretty-print a JWT segment-by-segment for the UI. */
function jwt_debug_table(string $token): string
{
    $p = jwt_split($token);
    if (!$p) {
        return '<div class="message error">Not a compact JWT (expected exactly three dot-separated segments).</div>';
    }
    $h = jwt_b64url_decode($p[0]);
    $c = jwt_b64url_decode($p[1]);
    $hp = json_decode($h, true);
    $cp = json_decode($c, true);

    $fmt = static function ($decoded, string $raw): string {
        if (is_array($decoded)) {
            return lk_esc(json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        }
        return '<span class="lk-ctl">invalid JSON</span> ' . lk_visible($raw);
    };

    return '<table class="lk-kv">'
        . '<tr><td>header (b64url)</td><td>' . lk_visible($p[0]) . '</td></tr>'
        . '<tr><td>header (json)</td><td><pre style="margin:0">' . $fmt($hp, $h) . '</pre></td></tr>'
        . '<tr><td>payload (b64url)</td><td>' . lk_visible($p[1]) . '</td></tr>'
        . '<tr><td>payload (json)</td><td><pre style="margin:0">' . $fmt($cp, $c) . '</pre></td></tr>'
        . '<tr><td>signature (b64url)</td><td>' . ($p[2] === ''
            ? '<span class="lk-empty">(empty - alg none style)</span>'
            : lk_visible($p[2])) . '</td></tr>'
        . '<tr><td>signature bytes</td><td>' . strlen(jwt_b64url_decode($p[2])) . '</td></tr>'
        . '</table>';
}

/* ------------------------------------------------------------------ JWK */

/** DER length prefix helper. */
function jwt_der_len(int $len): string
{
    if ($len < 0x80) {
        return chr($len);
    }
    $bytes = '';
    while ($len > 0) {
        $bytes = chr($len & 0xff) . $bytes;
        $len >>= 8;
    }
    return chr(0x80 | strlen($bytes)) . $bytes;
}

function jwt_der_int(string $bin): string
{
    $bin = ltrim($bin, "\x00");
    if ($bin === '' || ord($bin[0]) > 0x7f) {
        $bin = "\x00" . $bin;      // keep it positive
    }
    return "\x02" . jwt_der_len(strlen($bin)) . $bin;
}

/**
 * Turn the RSA modulus/exponent of a JWK into a PEM public key so that
 * openssl_verify() can use it. This is what a JWKS-consuming library does
 * internally; doing it by hand keeps level 8 honest.
 */
function jwt_jwk_to_pem(string $n_b64, string $e_b64): string
{
    $seq = jwt_der_int(jwt_b64url_decode($n_b64)) . jwt_der_int(jwt_b64url_decode($e_b64));
    $seq = "\x30" . jwt_der_len(strlen($seq)) . $seq;

    $bit = "\x03" . jwt_der_len(strlen($seq) + 1) . "\x00" . $seq;
    $alg = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";  // rsaEncryption NULL
    $der = "\x30" . jwt_der_len(strlen($alg) + strlen($bit)) . $alg . $bit;

    return "-----BEGIN PUBLIC KEY-----\n"
         . chunk_split(base64_encode($der), 64, "\n")
         . "-----END PUBLIC KEY-----\n";
}
