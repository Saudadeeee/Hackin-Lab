<?php
/**
 * JWT Workbench - the local, offline equivalent of jwt.io plus a cracker and a
 * keypair generator. Having real tooling on hand is what lets a level be about
 * the vulnerability instead of about base64 plumbing.
 */
require_once __DIR__ . '/helpers.php';

$lab = jwtlab();

$inToken   = trim((string)($_POST['token'] ?? ''));
$headerTxt = (string)($_POST['header'] ?? '');
$payloadTxt = (string)($_POST['payload'] ?? '');
$alg       = (string)($_POST['alg'] ?? 'HS256');
$secret    = (string)($_POST['secret'] ?? '');
$privPem   = (string)($_POST['privkey'] ?? '');
$action    = (string)($_POST['action'] ?? '');

$out       = '';
$outLabel  = '';
$notice    = '';

/* ---------------------------------------------------------------- decode */
if ($action === 'decode' && $inToken !== '') {
    $p = jwt_split($inToken);
    if (!$p) {
        $notice = '<div class="message error">Not three dot-separated segments.</div>';
    } else {
        $headerTxt  = jwt_b64url_decode($p[0]);
        $payloadTxt = jwt_b64url_decode($p[1]);
        $hp = json_decode($headerTxt, true);
        $pp = json_decode($payloadTxt, true);
        if (is_array($hp)) {
            $headerTxt = json_encode($hp, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        }
        if (is_array($pp)) {
            $payloadTxt = json_encode($pp, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        }
        $notice = '<div class="message info">Decoded. The editors below hold the raw JSON - edit and re-sign.</div>';
    }
}

/* ---------------------------------------------------------------- sign */
if ($action === 'sign') {
    // Raw text is used verbatim so duplicate keys / unicode escapes survive.
    $h64 = jwt_b64url_encode(preg_replace('/\s+(?=([^"]*"[^"]*")*[^"]*$)/', '', $headerTxt));
    $p64 = jwt_b64url_encode(preg_replace('/\s+(?=([^"]*"[^"]*")*[^"]*$)/', '', $payloadTxt));
    $in  = $h64 . '.' . $p64;

    switch ($alg) {
        case 'none':
            $out = $in . '.';
            break;
        case 'HS256':
            $out = $in . '.' . jwt_sign_hs256($in, $secret);
            break;
        case 'HS256-empty':
            $out = $in . '.' . jwt_sign_hs256($in, '');
            break;
        case 'HS256-pubkey':
            $out = $in . '.' . jwt_sign_hs256($in, jwt_public_key());
            break;
        case 'RS256':
            $sig = '';
            if ($privPem !== '' && @openssl_sign($in, $sig, $privPem, OPENSSL_ALGO_SHA256)) {
                $out = $in . '.' . jwt_b64url_encode($sig);
            } else {
                $notice = '<div class="message error">RSA signing failed - paste a valid PKCS#8/PKCS#1 private key.</div>';
            }
            break;
        case 'keep':
            $old = jwt_split($inToken);
            $out = $in . '.' . ($old ? $old[2] : '');
            break;
    }
    if ($out !== '') {
        $outLabel = 'Signed token';
    }
}

/* ---------------------------------------------------------------- crack */
$crackResult = '';
if ($action === 'crack' && $inToken !== '') {
    $p = jwt_split($inToken);
    if (!$p) {
        $crackResult = '<div class="message error">Not a JWT.</div>';
    } else {
        $words = jwt_wordlist();
        $extra = trim((string)($_POST['wordlist'] ?? ''));
        if ($extra !== '') {
            $words = array_merge(preg_split('/\r?\n/', $extra), $words);
        }
        $found = null;
        $tried = 0;
        $t0    = microtime(true);
        foreach ($words as $w) {
            $w = rtrim($w, "\r");
            if ($w === '') {
                continue;
            }
            $tried++;
            if (hash_equals(jwt_sign_hs256($p[0] . '.' . $p[1], $w), $p[2])) {
                $found = $w;
                break;
            }
        }
        $ms = round((microtime(true) - $t0) * 1000, 1);
        $crackResult = $found === null
            ? '<div class="message error">No candidate matched after ' . $tried . ' guesses (' . $ms . ' ms). '
              . 'Add your own wordlist below, or the key is genuinely strong.</div>'
            : '<div class="message success">Secret found after ' . $tried . ' guesses (' . $ms . ' ms): <code>'
              . lk_esc($found) . '</code><br><span class="text-muted">Note that the server was never contacted. '
              . 'HS256 cracking is entirely offline - which is why HMAC secrets need real entropy.</span></div>';
    }
}

/* ---------------------------------------------------------------- keygen */
$keygen = '';
if ($action === 'keygen') {
    $res = @openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    if (!$res) {
        $keygen = '<div class="message error">openssl_pkey_new() failed in this container.</div>';
    } else {
        openssl_pkey_export($res, $priv);
        $det = openssl_pkey_get_details($res);
        $kid = 'attacker-' . substr(sha1($det['key']), 0, 8);
        $jwks = json_encode([
            'keys' => [[
                'kty' => 'RSA',
                'kid' => $kid,
                'use' => 'sig',
                'alg' => 'RS256',
                'n'   => jwt_b64url_encode($det['rsa']['n']),
                'e'   => jwt_b64url_encode($det['rsa']['e']),
            ]],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        $keygen = '<div class="lk-box"><h4><span class="lk-tag">KEYPAIR</span>Fresh RSA-2048 - kid <code>'
            . lk_esc($kid) . '</code></h4><div class="lk-body">'
            . '<div class="form-group"><label class="form-label">Private key (sign with this)</label>'
            . '<textarea class="form-control jwt-ta" rows="6" onclick="this.select()">' . lk_esc($priv) . '</textarea></div>'
            . '<div class="form-group"><label class="form-label">JWKS (publish this at your jku URL)</label>'
            . '<textarea class="form-control jwt-ta" rows="8" onclick="this.select()">' . lk_esc($jwks) . '</textarea></div>'
            . '<p class="text-muted">Paste the JWKS into <a href="paste.php">paste.php</a>, then use the returned URL as your '
            . '<code>jku</code>. Remember to keep the <code>kid</code> in your token header matching the JWKS entry.</p>'
            . '</div></div>';
    }
}

/* ---------------------------------------------------------------- b64 tool */
$b64out = '';
if ($action === 'b64') {
    $val = (string)($_POST['b64in'] ?? '');
    $b64out = ($_POST['b64dir'] ?? 'enc') === 'enc'
        ? jwt_b64url_encode($val)
        : jwt_b64url_decode($val);
}

function jwt_wordlist(): array
{
    return [
        'secret', 'password', 'password1', '123456', '12345678', 'qwerty', 'letmein', 'letmein123',
        'admin', 'admin123', 'root', 'toor', 'changeme', 'default', 'jwtsecret', 'jwt_secret',
        'supersecret', 'super_secret', 'topsecret', 'mysecret', 'signingkey', 'signing_key',
        'sunshine', 'iloveyou', 'monkey', 'dragon', 'football', 'baseball', 'shadow', 'master',
        'hackinlab', 'hackme', 'test', 'testing', 'dev', 'development', 'staging', 'production',
        'key', 'privatekey', 'sessionkey', 'token', 'tokensecret', 'apikey', 'api_key',
        'p@ssw0rd', 'Password1', 'Passw0rd!', 'welcome', 'welcome1', 'trustno1', 'ninja',
        'abc123', 'a1b2c3', 'qwerty123', 'zaq12wsx', '1qaz2wsx', 'asdfgh', 'zxcvbn',
        'node', 'express', 'laravel', 'symfony', 'django', 'flask', 'spring', 'jsonwebtoken',
    ];
}
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>JWT Workbench — <?= lk_esc($lab['name']) ?></title>
<link rel="stylesheet" href="css/styles.css">
<?= jwt_extra_head() ?>
<style>.wb-grid{display:grid;grid-template-columns:1fr;gap:1rem}@media(min-width:1050px){.wb-grid{grid-template-columns:1fr 1fr}}</style>
</head>
<body>
<header class="header">
    <div class="header-left"><h1>JWT Workbench</h1><p>Offline decode · edit · sign · crack · keygen</p></div>
    <div class="header-right"><a href="index.php" class="back-btn">&larr; Levels</a></div>
</header>

<div class="container">

    <div class="scenario">
        <strong>Why this tool exists.</strong> Every attack in this lab is a claim about how the
        <em>server</em> decides to trust a token. The plumbing — base64url, HMAC, PEM — is not the lesson.
        Do the plumbing here so each level stays about the actual reasoning.
    </div>

    <?= $notice ?>

    <div class="wb-grid">
        <div class="code-panel">
            <div class="panel-header"><span class="panel-label">Decode &amp; Re-sign</span></div>
            <div class="panel-body">
                <form method="post">
                    <div class="form-group">
                        <label class="form-label">Token in</label>
                        <textarea name="token" rows="4" class="form-control jwt-ta" spellcheck="false"><?= lk_esc($inToken) ?></textarea>
                    </div>
                    <button class="btn btn-outline" type="submit" name="action" value="decode">Decode &darr;</button>
                </form>

                <form method="post" style="margin-top:1rem">
                    <input type="hidden" name="token" value="<?= lk_esc($inToken) ?>">
                    <div class="form-group">
                        <label class="form-label">Header JSON (sent verbatim — whitespace outside strings is stripped)</label>
                        <textarea name="header" rows="4" class="form-control jwt-ta" spellcheck="false"><?= lk_esc($headerTxt !== '' ? $headerTxt : "{\n  \"typ\": \"JWT\",\n  \"alg\": \"HS256\"\n}") ?></textarea>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Payload JSON (duplicate keys and <code>\uXXXX</code> escapes are preserved)</label>
                        <textarea name="payload" rows="8" class="form-control jwt-ta" spellcheck="false"><?= lk_esc($payloadTxt !== '' ? $payloadTxt : "{\n  \"sub\": \"guest\",\n  \"role\": \"user\",\n  \"exp\": 9999999999\n}") ?></textarea>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Algorithm</label>
                        <select name="alg" class="form-control">
                            <?php foreach ([
                                'HS256'        => 'HS256 — HMAC with the secret below',
                                'HS256-empty'  => 'HS256 — empty secret ("")',
                                'HS256-pubkey' => 'HS256 — secret = server RSA public key PEM',
                                'RS256'        => 'RS256 — sign with the private key below',
                                'none'         => 'none — no signature, keep the trailing dot',
                                'keep'         => 'keep — reuse the signature from "Token in"',
                            ] as $k => $lbl): ?>
                            <option value="<?= $k ?>"<?= $alg === $k ? ' selected' : '' ?>><?= lk_esc($lbl) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">HMAC secret</label>
                        <input type="text" name="secret" class="form-control jwt-ta" value="<?= lk_esc($secret) ?>" spellcheck="false">
                    </div>
                    <div class="form-group">
                        <label class="form-label">RSA private key (PEM, for RS256)</label>
                        <textarea name="privkey" rows="4" class="form-control jwt-ta" spellcheck="false"><?= lk_esc($privPem) ?></textarea>
                    </div>
                    <button class="btn btn-primary" type="submit" name="action" value="sign">Sign &rarr;</button>
                </form>

                <?php if ($out !== ''): ?>
                <div class="lk-box lk-why" style="margin-top:1rem">
                    <h4><span class="lk-tag lk-tag-good"><?= lk_esc($outLabel) ?></span></h4>
                    <div class="lk-body">
                        <textarea class="form-control jwt-ta" rows="4" onclick="this.select()"><?= lk_esc($out) ?></textarea>
                    </div>
                </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="challenge-panel">
            <div class="panel-header"><span class="panel-label">Offline attacks</span></div>
            <div class="panel-body">

                <div class="lk-box">
                    <h4><span class="lk-tag">CRACK</span>HS256 dictionary attack</h4>
                    <div class="lk-body">
                        <p>HMAC verification is a pure function of the token and the key. That means an attacker
                        holding one token can test candidate keys locally, forever, without ever touching the server —
                        no rate limit, no logs, no lockout.</p>
                        <form method="post">
                            <input type="hidden" name="token" value="<?= lk_esc($inToken) ?>">
                            <div class="form-group">
                                <label class="form-label">Extra candidates (one per line, tried first)</label>
                                <textarea name="wordlist" rows="4" class="form-control jwt-ta" spellcheck="false"><?= lk_esc($_POST['wordlist'] ?? '') ?></textarea>
                            </div>
                            <button class="btn btn-outline" type="submit" name="action" value="crack">Crack the token above</button>
                        </form>
                        <?= $crackResult ?>
                    </div>
                </div>

                <div class="lk-box">
                    <h4><span class="lk-tag">KEYGEN</span>Attacker RSA keypair + JWKS</h4>
                    <div class="lk-body">
                        <p>Needed when a level lets you choose <em>where</em> the key set comes from
                        (<code>jku</code>, <code>x5u</code>). You publish a key you own; the server trusts it.</p>
                        <form method="post"><button class="btn btn-outline" type="submit" name="action" value="keygen">Generate RSA-2048</button></form>
                    </div>
                </div>
                <?= $keygen ?>

                <div class="lk-box">
                    <h4><span class="lk-tag">B64URL</span>base64url encode / decode</h4>
                    <div class="lk-body">
                        <form method="post">
                            <div class="form-group">
                                <textarea name="b64in" rows="3" class="form-control jwt-ta" spellcheck="false"><?= lk_esc($_POST['b64in'] ?? '') ?></textarea>
                            </div>
                            <div class="form-group">
                                <select name="b64dir" class="form-control">
                                    <option value="enc">encode</option>
                                    <option value="dec"<?= ($_POST['b64dir'] ?? '') === 'dec' ? ' selected' : '' ?>>decode</option>
                                </select>
                            </div>
                            <button class="btn btn-outline" type="submit" name="action" value="b64">Run</button>
                        </form>
                        <?php if ($b64out !== ''): ?>
                            <div class="output-box"><?= lk_visible($b64out, 2000) ?></div>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="lk-box">
                    <h4><span class="lk-tag">SERVER</span>Public material</h4>
                    <div class="lk-body">
                        <p>These are <em>meant</em> to be public. Several levels turn that against the server.</p>
                        <ul>
                            <li><a href="jwks.php">jwks.php</a> — the issuer's JSON Web Key Set</li>
                            <li><a href="jwks.php?pem=1">jwks.php?pem=1</a> — the same key as PEM (exact bytes matter for HS256 confusion)</li>
                            <li><a href="paste.php">paste.php</a> — host your own JSON at a URL on this origin</li>
                        </ul>
                    </div>
                </div>

            </div>
        </div>
    </div>
</div>
</body>
</html>
