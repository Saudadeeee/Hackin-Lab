<?php
require_once __DIR__ . '/helpers.php';

$L    = 8;
$meta = jwt_levels()[$L];

const JKU_TRUSTED_HOST = 'keys.hackinlab.internal';
const JKU_DEFAULT      = 'http://keys.hackinlab.internal/jwks.php';

$issued = jwt_encode(
    ['typ' => 'JWT', 'alg' => 'RS256', 'kid' => 'main-2024', 'jku' => JKU_DEFAULT],
    ['sub' => 'guest', 'name' => 'Guest User', 'role' => 'user',
     'iss' => 'https://auth.hackinlab.internal', 'iat' => time(), 'exp' => time() + 3600],
    jwt_private_key()
);

$token    = trim((string)($_POST['token'] ?? ''));
$flag     = '';
$result   = '';
$pipeline = [];

/** Fetch a key set. http/https only, short timeout - this part is not the bug. */
function jku_fetch(string $url): ?array
{
    $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
    if (!in_array($scheme, ['http', 'https'], true)) {
        return null;
    }
    $ctx  = stream_context_create(['http' => ['timeout' => 3, 'ignore_errors' => true]]);
    $body = @file_get_contents($url, false, $ctx);
    if ($body === false) {
        return null;
    }
    $json = json_decode($body, true);
    return is_array($json) ? $json : null;
}

if ($token !== '') {
    $header = jwt_header($token);
    $alg    = $header['alg'] ?? '';
    $kid    = (string)($header['kid'] ?? '');
    $jku    = (string)($header['jku'] ?? JKU_DEFAULT);

    // ── The vulnerable allowlist: "does the trusted name appear anywhere?" ──
    $allowed = strpos($jku, JKU_TRUSTED_HOST) !== false;

    $jwks = $allowed ? jku_fetch($jku) : null;
    $pem  = '';
    $picked = null;
    if ($jwks && !empty($jwks['keys']) && is_array($jwks['keys'])) {
        foreach ($jwks['keys'] as $k) {
            if (($k['kid'] ?? null) === $kid && ($k['kty'] ?? '') === 'RSA') {
                $picked = $k;
                break;
            }
        }
        if ($picked === null) {
            $picked = $jwks['keys'][0];      // fall back to the first key offered
        }
        if (!empty($picked['n']) && !empty($picked['e'])) {
            $pem = jwt_jwk_to_pem((string)$picked['n'], (string)$picked['e']);
        }
    }

    $verified = ($alg === 'RS256') && $pem !== '' && jwt_verify_rs256($token, $pem);
    $claims   = $verified ? jwt_claims_unverified($token) : null;
    $role     = $claims['role'] ?? '';

    $realHost = (string)parse_url($jku, PHP_URL_HOST);

    $pipeline = [
        ['label' => '$jku = $header["jku"]', 'value' => $jku],
        ['label' => 'strpos($jku, "' . JKU_TRUSTED_HOST . '") !== false',
         'value' => $allowed ? 'allowed' : 'rejected',
         'note'  => 'Substring test on the whole URL. The parsed host is actually <code>'
                    . lk_esc($realHost !== '' ? $realHost : '(none)') . '</code> — the check never looked.',
         'verdict' => $allowed ? 'pass' : 'block'],
        ['label' => 'GET ' . ($allowed ? $jku : '(not fetched)'),
         'value' => $jwks === null ? '(no key set retrieved)' : json_encode($picked, JSON_UNESCAPED_SLASHES),
         'note'  => $picked !== null ? 'This key now decides whether your signature is genuine.' : ''],
        ['label' => 'openssl_verify($input, $sig, $pem)',
         'value' => $verified ? 'verified = true' : 'verified = false',
         'verdict' => $verified ? 'pass' : 'block'],
        ['label' => '$claims["role"]', 'value' => (string)$role, 'verdict' => $role === 'admin' ? 'pass' : null],
    ];

    if (!$allowed) {
        $result = jwt_decision(false, '', 'jku host not trusted.');
    } elseif ($jwks === null) {
        $result = jwt_decision(false, '', 'Could not retrieve a JSON key set from that URL.');
    } elseif (!$verified) {
        $result = jwt_decision(false, '', 'Signature does not verify against the fetched key.');
    } elseif ($role === 'admin') {
        $flag   = jwt_flag($L);
        $result = jwt_decision(true, 'admin', 'Admin console unlocked.');
    } else {
        $result = jwt_decision(true, (string)$role, 'Verified against the fetched key, role is not admin.');
    }
}

$code = <<<'PHP'
// Federated issuers publish their key sets; tokens point at theirs.
$jku = $header['jku'] ?? 'http://keys.hackinlab.internal/jwks.php';

// "Only fetch from our own key host."
if (strpos($jku, 'keys.hackinlab.internal') === false) {
    return deny('untrusted jku');
}

$jwks = json_decode(file_get_contents($jku), true);
$jwk  = find_by_kid($jwks['keys'], $header['kid']) ?? $jwks['keys'][0];
$pem  = jwk_to_pem($jwk['n'], $jwk['e']);

if (jwt_verify_rs256($token, $pem)
    && (jwt_claims_unverified($token)['role'] ?? '') === 'admin') {
    grant_admin();
}
PHP;

$fixBad = <<<'PHP'
if (strpos($jku, 'keys.hackinlab.internal') === false) {
    return deny('untrusted jku');
}
$jwks = json_decode(file_get_contents($jku), true);
PHP;

$fixGood = <<<'PHP'
// Do not take a URL from the token at all. Pin the key set per issuer.
const JWKS_FOR_ISSUER = [
    'https://auth.hackinlab.internal' => 'https://keys.hackinlab.internal/jwks.php',
];

$iss = $unverifiedClaims['iss'] ?? '';
if (!isset(JWKS_FOR_ISSUER[$iss])) {
    return deny('unknown issuer');
}
$jwks = $cache->fetch(JWKS_FOR_ISSUER[$iss]);   // fixed URL, cached, TLS-verified

// If a URL from the token is genuinely unavoidable, compare the PARSED host
// for equality - never a substring of the whole URL:
//   $host = parse_url($jku, PHP_URL_HOST);
//   if ($host !== 'keys.hackinlab.internal') deny();
// and re-check it after every redirect.
PHP;

lk_page([
    'lab'        => jwtlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => jwt_extra_head(),

    'code'       => $code,
    'vuln_lines' => [5, 6, 9],
    'annotation' => 'The token names the URL that supplies the verification key, and the allowlist asks
        <em>"does this string contain our hostname?"</em> instead of <em>"is our hostname the authority of this
        URL?"</em>. Those are very different questions.',

    'theory' => '<p>URL allowlists fail because a URL has many places a string can hide: userinfo
        (<code>http://trusted@evil.com/</code>), path (<code>http://evil.com/trusted</code>), query
        (<code>?x=trusted</code>), fragment, and the host itself. A substring test cannot tell them apart; only
        parsing can.</p>
        <p>The authority of a URL is what appears between <code>//</code> and the next <code>/</code>,
        <code>?</code> or <code>#</code>. Everything after that is under the control of whoever owns that authority.
        So the only sound check is: parse, take the host, compare for equality against a fixed list.</p>
        <p>And even a correct host check is not enough on its own here — <code>jku</code> makes key selection a
        network operation, which drags in redirects, DNS rebinding, and SSRF. The genuinely safe design is to not
        accept a key-set location from the token at all.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The same reasoning applies to <code>x5u</code> (certificate URL) and to any OIDC discovery flow
            that derives endpoints from an attacker-influenced issuer string.',
    ],

    'scenario' => '<strong>Scenario:</strong> a federated setup. Tokens carry a <code>jku</code> pointing at their
        issuer\'s key set; the verifier fetches it and uses the matching <code>kid</code>. The trusted key host is
        <code>' . JKU_TRUSTED_HOST . '</code>.
        <br><strong>Goal:</strong> get an RS256 admin token verified against a key <em>you</em> generated.',

    'model' => [
        'title' => 'The four steps, and where each one happens',
        'html'  => '<ol>
            <li><strong>Generate a keypair.</strong> Workbench &rarr; <em>Generate RSA-2048</em>. Keep the private key
                and the JWKS it prints; note the <code>kid</code>.</li>
            <li><strong>Publish the JWKS.</strong> Paste it into <a href="paste.php">paste.php</a>. Use the
                <em>server-side URL</em> it gives you (<code>http://localhost/paste.php?id=…</code>) — the verifier
                fetches from inside the container, where the host port does not exist.</li>
            <li><strong>Defeat the allowlist.</strong> Append the trusted name somewhere harmless:
                <code>&amp;h=' . JKU_TRUSTED_HOST . '</code>. The substring is now present; the authority is still yours.</li>
            <li><strong>Sign.</strong> RS256, private key from step 1, header carrying your <code>kid</code> and that
                <code>jku</code>, payload with <code>role: admin</code>.</li>
        </ol>
        <p>If step 4 fails, check that the <code>kid</code> in your header matches the one in your JWKS — otherwise
        the verifier falls back to the first key in the set, which may not be yours.</p>',
    ],

    'form'     => jwt_token_form($issued, $token),
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The server fetched your key and used it to confirm your signature.',
    'why'      => '<p>Read trace step 2 again: the check said <em>allowed</em> while the parsed host was not the
        trusted one. That single line is the whole vulnerability — the allowlist and the fetcher disagreed about
        what part of the URL matters.</p>
        <p>Everything after that was the server behaving correctly. It fetched a key set, selected the key your
        <code>kid</code> named, and verified your RSA signature against it. The signature <em>is</em> genuine. It is
        simply genuine for a key that should never have been in scope.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'token',
        'method' => 'POST',
        'action' => 'level8.php',
        'items'  => [
            ['q' => 'Is jku honoured at all, or ignored in favour of a pinned URL?',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'RS256', 'kid' => 'main-2024',
                 'jku' => 'http://keys.hackinlab.internal/jwks.php'],
                 ['sub' => 'guest', 'role' => 'user', 'exp' => 9999999999], jwt_private_key()),
             'learn'   => 'Baseline: the legitimate key set, correctly signed. Establish that the happy path works before you try to bend it.'],
            ['q' => 'Does the allowlist look at the host, or at the whole string?',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'RS256', 'kid' => 'main-2024',
                 'jku' => 'http://localhost/jwks.php?h=keys.hackinlab.internal'],
                 ['sub' => 'guest', 'role' => 'user', 'exp' => 9999999999], jwt_private_key()),
             'learn'   => 'Same key set, reached through a URL whose host is <em>not</em> trusted. If this verifies, the allowlist is a substring test and the level is open.'],
            ['q' => 'What happens when the fetch fails — fail closed, or fall back to a default key?',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'RS256', 'kid' => 'main-2024',
                 'jku' => 'http://keys.hackinlab.internal/nope-404.php'],
                 ['sub' => 'guest', 'role' => 'user', 'exp' => 9999999999], jwt_private_key()),
             'learn'   => 'A verifier that falls back to a cached or hardcoded key on fetch failure is a different bug worth knowing about — and this probe is how you find it.'],
        ],
    ],
    'hints' => jwt_hints($L),
]);
