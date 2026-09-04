<?php
/**
 * Crypto Oracle Lab · primitives
 * ---------------------------------------------------------------------------
 * Everything here is real cryptography used badly. AES comes from OpenSSL;
 * SHA-1 is reimplemented so that level 7 can resume the compression function
 * from a captured state, which is the whole point of a length-extension attack.
 *
 * Keys are derived deterministically from a lab constant so that tokens stay
 * stable across container restarts - a learner mid-attack should not lose
 * their ciphertexts because Docker was restarted.
 */

const CRYPTO_LAB_SEED = 'hackinlab-crypto-oracle-v1';

/** 16-byte AES key, fixed per level. */
function cl_key(int $level): string
{
    return substr(hash('sha256', CRYPTO_LAB_SEED . '|key|' . $level, true), 0, 16);
}

/** Fixed IV where a level deliberately wants a static one. */
function cl_iv(int $level): string
{
    return substr(hash('sha256', CRYPTO_LAB_SEED . '|iv|' . $level, true), 0, 16);
}

/* ------------------------------------------------------------------ encoding */

function cl_hex(string $bin): string
{
    return bin2hex($bin);
}

function cl_unhex(string $hex): string
{
    $hex = preg_replace('/[^0-9a-fA-F]/', '', $hex);
    if (strlen($hex) % 2 !== 0) {
        $hex = substr($hex, 0, -1);
    }
    return (string)@hex2bin($hex);
}

function cl_b64(string $bin): string
{
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

function cl_unb64(string $txt): string
{
    $txt = strtr(trim($txt), '-_', '+/');
    $pad = strlen($txt) % 4;
    if ($pad) {
        $txt .= str_repeat('=', 4 - $pad);
    }
    return (string)base64_decode($txt, false);
}

/** XOR two byte strings, truncated to the shorter one. */
function cl_xor(string $a, string $b): string
{
    $n   = min(strlen($a), strlen($b));
    $out = '';
    for ($i = 0; $i < $n; $i++) {
        $out .= chr(ord($a[$i]) ^ ord($b[$i]));
    }
    return $out;
}

/** Repeating-key XOR (the "encryption" level 2 mistakes for a cipher). */
function cl_xor_repeat(string $data, string $key): string
{
    if ($key === '') {
        return $data;
    }
    $out = '';
    for ($i = 0, $n = strlen($data); $i < $n; $i++) {
        $out .= chr(ord($data[$i]) ^ ord($key[$i % strlen($key)]));
    }
    return $out;
}

/* ------------------------------------------------------------------ padding */

function cl_pkcs7_pad(string $data, int $block = 16): string
{
    $n = $block - (strlen($data) % $block);
    return $data . str_repeat(chr($n), $n);
}

/**
 * Strict PKCS#7 unpad. Returns null on invalid padding - the distinction
 * between "invalid padding" and "valid padding, bad content" is exactly the
 * oracle level 6 hands the attacker.
 */
function cl_pkcs7_unpad(string $data, int $block = 16): ?string
{
    $len = strlen($data);
    if ($len === 0 || $len % $block !== 0) {
        return null;
    }
    $n = ord($data[$len - 1]);
    if ($n < 1 || $n > $block || $n > $len) {
        return null;
    }
    for ($i = $len - $n; $i < $len; $i++) {
        if (ord($data[$i]) !== $n) {
            return null;
        }
    }
    return substr($data, 0, $len - $n);
}

/* ------------------------------------------------------------------ AES */

function cl_aes_ecb_encrypt(string $plain, string $key): string
{
    return (string)openssl_encrypt(
        cl_pkcs7_pad($plain), 'aes-128-ecb', $key,
        OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
    );
}

function cl_aes_ecb_decrypt_raw(string $cipher, string $key): string
{
    return (string)openssl_decrypt(
        $cipher, 'aes-128-ecb', $key,
        OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
    );
}

function cl_aes_cbc_encrypt(string $plain, string $key, string $iv): string
{
    return (string)openssl_encrypt(
        cl_pkcs7_pad($plain), 'aes-128-cbc', $key,
        OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv
    );
}

/** Decrypt without removing padding, so a level can inspect the padding itself. */
function cl_aes_cbc_decrypt_raw(string $cipher, string $key, string $iv): string
{
    return (string)openssl_decrypt(
        $cipher, 'aes-128-cbc', $key,
        OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv
    );
}

/** AES-128-CTR, so a level can demonstrate keystream reuse. */
function cl_aes_ctr(string $data, string $key, string $nonce): string
{
    return (string)openssl_encrypt(
        $data, 'aes-128-ctr', $key, OPENSSL_RAW_DATA, $nonce
    );
}

/** Split a byte string into 16-byte blocks for display. */
function cl_blocks(string $bin, int $size = 16): array
{
    return str_split($bin, $size) ?: [];
}

/** True when two or more 16-byte blocks are identical - the ECB fingerprint. */
function cl_has_repeated_block(string $cipher, int $size = 16): bool
{
    $b = cl_blocks($cipher, $size);
    return count($b) !== count(array_unique($b));
}

/* ------------------------------------------------------------------ SHA-1 */

/**
 * SHA-1 that can start from an arbitrary internal state and an arbitrary
 * prior message length. With the default state this is plain SHA-1; with a
 * state lifted from a published digest it continues someone else's hash,
 * which is what makes MAC = H(secret || message) forgeable.
 */
function cl_sha1(string $message, ?array $state = null, int $priorLen = 0): string
{
    $h = $state ?? [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    $total  = $priorLen + strlen($message);
    $padded = $message . cl_sha1_padding($total, strlen($message));

    foreach (str_split($padded, 64) as $chunk) {
        $w = array_values(unpack('N16', $chunk));
        for ($i = 16; $i < 80; $i++) {
            $w[$i] = cl_rotl($w[$i - 3] ^ $w[$i - 8] ^ $w[$i - 14] ^ $w[$i - 16], 1);
        }
        [$a, $b, $c, $d, $e] = $h;
        for ($i = 0; $i < 80; $i++) {
            if ($i < 20)      { $f = ($b & $c) | (~$b & $d);          $k = 0x5A827999; }
            elseif ($i < 40)  { $f = $b ^ $c ^ $d;                    $k = 0x6ED9EBA1; }
            elseif ($i < 60)  { $f = ($b & $c) | ($b & $d) | ($c & $d); $k = 0x8F1BBCDC; }
            else              { $f = $b ^ $c ^ $d;                    $k = 0xCA62C1D6; }

            $tmp = (cl_rotl($a, 5) + $f + $e + $k + $w[$i]) & 0xFFFFFFFF;
            $e = $d;
            $d = $c;
            $c = cl_rotl($b, 30);
            $b = $a;
            $a = $tmp;
        }
        $h[0] = ($h[0] + $a) & 0xFFFFFFFF;
        $h[1] = ($h[1] + $b) & 0xFFFFFFFF;
        $h[2] = ($h[2] + $c) & 0xFFFFFFFF;
        $h[3] = ($h[3] + $d) & 0xFFFFFFFF;
        $h[4] = ($h[4] + $e) & 0xFFFFFFFF;
    }
    return vsprintf('%08x%08x%08x%08x%08x', $h);
}

function cl_rotl(int $v, int $n): int
{
    $v &= 0xFFFFFFFF;
    return (($v << $n) | ($v >> (32 - $n))) & 0xFFFFFFFF;
}

/**
 * The glue padding SHA-1 appends: 0x80, zeros, then the TOTAL message length
 * in bits as a 64-bit big-endian integer. An attacker can compute this for a
 * message they cannot see, provided they know its length.
 */
function cl_sha1_padding(int $totalLen, int $chunkLen = 0): string
{
    $padLen = (56 - ($totalLen + 1)) % 64;
    if ($padLen < 0) {
        $padLen += 64;
    }
    return "\x80" . str_repeat("\x00", $padLen) . pack('J', $totalLen * 8);
}

/** Turn a published SHA-1 digest back into the five internal registers. */
function cl_sha1_state_from_digest(string $hex): array
{
    return array_map('hexdec', str_split(strtolower(trim($hex)), 8));
}

/* ------------------------------------------------------------------ display */

/** Render a ciphertext as numbered 16-byte blocks, repeats highlighted. */
function cl_block_table(string $bin, int $size = 16): string
{
    $blocks = cl_blocks($bin, $size);
    $counts = array_count_values(array_map('bin2hex', $blocks));
    $out    = '<table class="lk-kv"><tr><td>block</td><td>hex</td></tr>';
    foreach ($blocks as $i => $b) {
        $hex  = bin2hex($b);
        $dupe = ($counts[$hex] ?? 0) > 1;
        $out .= '<tr><td>' . $i . ($dupe ? ' <span class="lk-chip lk-chip-bad">repeat</span>' : '') . '</td>'
              . '<td' . ($dupe ? ' style="color:#b5766e"' : '') . '>' . $hex . '</td></tr>';
    }
    return $out . '</table>';
}
