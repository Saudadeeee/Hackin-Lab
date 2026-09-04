<?php
/**
 * JWT Lab · lab metadata, flags, hints and shared level UI.
 */

require_once __DIR__ . '/lab_kit.php';
require_once __DIR__ . '/jwt.php';

function jwtlab(): array
{
    return [
        'slug'    => 'jwt',
        'name'    => 'JWT & Token Forgery Lab',
        'icon'    => 'JWT',
        'total'   => 10,
        'tagline' => 'Ten ways a signature check can be worthless',
    ];
}

function jwt_flag(int $level): string
{
    $flags = [
        1  => 'FLAG{jwt_is_encoding_not_encryption}',
        2  => 'FLAG{alg_none_is_not_an_algorithm}',
        3  => 'FLAG{decode_is_not_verify}',
        4  => 'FLAG{hmac_secret_was_in_rockyou}',
        5  => 'FLAG{public_key_became_the_hmac_secret}',
        6  => 'FLAG{kid_walked_out_of_the_keystore}',
        7  => 'FLAG{kid_selected_its_own_key}',
        8  => 'FLAG{jku_pointed_at_my_own_jwks}',
        9  => 'FLAG{two_readers_one_token}',
        10 => 'FLAG{duplicate_keys_split_the_parsers}',
    ];
    return $flags[$level] ?? '';
}

function jwt_levels(): array
{
    return [
        1 => [
            'title'      => 'Read the Token',
            'difficulty' => 'Easy',
            'skill'      => 'JWT structure, base64url, why claims are public',
            'desc'       => 'A JWT is signed, not encrypted. Decode the token the server handed you and read the claim it assumed you could not see.',
        ],
        2 => [
            'title'      => 'alg: none',
            'difficulty' => 'Easy',
            'skill'      => 'Algorithm chosen by attacker-controlled header',
            'desc'       => 'The verifier reads the algorithm out of the token header and honours <code>none</code>, which means "trust me, no signature needed".',
        ],
        3 => [
            'title'      => 'Decode Instead of Verify',
            'difficulty' => 'Easy',
            'skill'      => 'decode() vs verify() - the most common JWT bug in the wild',
            'desc'       => 'The endpoint never calls a verify function at all. It base64-decodes the payload and trusts it. Any signature will do.',
        ],
        4 => [
            'title'      => 'Weak HMAC Secret',
            'difficulty' => 'Medium',
            'skill'      => 'Offline brute force of HS256, why key entropy matters',
            'desc'       => 'Verification is correct and the algorithm is pinned. The secret, however, is a dictionary word - and HS256 can be cracked offline.',
        ],
        5 => [
            'title'      => 'RS256 to HS256 Confusion',
            'difficulty' => 'Hard',
            'skill'      => 'Algorithm confusion, public key used as symmetric key',
            'desc'       => 'The server picks the verification function from the header. Switch RS256 to HS256 and the public key becomes a secret you already know.',
        ],
        6 => [
            'title'      => 'kid Path Traversal',
            'difficulty' => 'Hard',
            'skill'      => 'Header parameters as file paths, predictable-content key files',
            'desc'       => 'The <code>kid</code> header selects a key file on disk. Point it somewhere outside the key store and you control the signing key.',
        ],
        7 => [
            'title'      => 'kid SQL Injection',
            'difficulty' => 'Hard',
            'skill'      => 'Header parameters reaching a database, key material injection',
            'desc'       => 'The <code>kid</code> is looked up in a key table with string concatenation. Inject a UNION and hand the verifier a key of your choosing.',
        ],
        8 => [
            'title'      => 'jku Header Hijack',
            'difficulty' => 'Hard',
            'skill'      => 'Remote key sets, allowlists that check the wrong part of a URL',
            'desc'       => 'The verifier fetches the key set from the URL in the <code>jku</code> header. The allowlist only checks that the host appears somewhere in the string.',
        ],
        9 => [
            'title'      => 'Claim Precedence Confusion',
            'difficulty' => 'Expert',
            'skill'      => 'Two components reading different claims from one token',
            'desc'       => 'The auth middleware reads one claim, the application reads another. Satisfy the guard with one and privilege yourself with the other.',
        ],
        10 => [
            'title'      => 'Duplicate JSON Keys',
            'difficulty' => 'Expert',
            'skill'      => 'Parser differential: regex WAF vs JSON parser',
            'desc'       => 'A regex WAF inspects the payload before the JSON parser sees it. The two disagree about which value of a repeated key counts.',
        ],
    ];
}

/* =========================================================================
 * Hints (5 per level: concept -> observation -> technique -> shape -> payload)
 * ===================================================================== */

function jwt_hints(int $level): array
{
    $h = [
        1 => [
            'A JWT has three dot-separated segments: <code>header.payload.signature</code>. The first two are <strong>base64url of JSON</strong>, not ciphertext.',
            'base64url is base64 with <code>+</code> replaced by <code>-</code>, <code>/</code> replaced by <code>_</code>, and <code>=</code> padding stripped. Nothing secret happens here.',
            'Open the <a href="tools.php">JWT Workbench</a>, paste the token, and read the decoded payload. No key needed - decoding never touches the signature.',
            'The claim you want is not <code>role</code>. Look for a field the developer assumed the browser would never read.',
            'Decode the payload and submit the value of the <code>internal_note</code> claim into the answer box.',
        ],
        2 => [
            'Look at the verification code: <code>$alg = $header["alg"]</code>. The <em>token</em> decides how the token is checked. That is the bug in one line.',
            'The JWA spec defines <code>none</code> as an algorithm meaning "unsecured JWT". A verifier that honours it accepts any payload.',
            'For <code>alg: none</code> the signature segment must be <strong>empty</strong>, but the trailing dot stays: <code>header.payload.</code>',
            'Change the header to <code>{"typ":"JWT","alg":"none"}</code>, change <code>"role":"user"</code> to <code>"role":"admin"</code>, re-encode both, and append a dot.',
            'In the <a href="tools.php">Workbench</a>: paste the token, set role to admin, choose algorithm <code>none</code>, sign, and submit the result.',
        ],
        3 => [
            'Search the level source for the string <code>verify</code>. It is not there. That is the whole finding.',
            'The endpoint calls <code>jwt_claims_unverified()</code>, which is <code>json_decode(base64url_decode($payload))</code> and nothing else.',
            'Because nothing is verified, the signature segment is decoration. It can be the original one, or garbage, or a single character.',
            'Keep the header as-is, edit only the payload so <code>role</code> is <code>admin</code>, and leave the old signature attached.',
            'Workbench &rarr; paste token &rarr; set <code>role: admin</code> &rarr; sign with algorithm <code>keep signature (none applied)</code> &rarr; submit.',
        ],
        4 => [
            'This level verifies correctly and pins the algorithm to HS256. There is no logic flaw left - so attack the key itself.',
            'HS256 is <code>HMAC-SHA256(header + "." + payload, secret)</code>. Anyone holding the token can test candidate secrets <strong>offline</strong>, at millions per second, with no requests to the server.',
            'The lab ships a small wordlist so you can watch the attack work. Use the cracker on this page, or run <code>hashcat -m 16500</code> against the token with rockyou.',
            'Once a candidate secret reproduces the token signature, you have the key: you can now mint <em>any</em> claims you want.',
            'Crack the secret, then Workbench &rarr; set <code>role: admin</code> &rarr; algorithm HS256 &rarr; secret = the cracked word &rarr; submit.',
        ],
        5 => [
            'The header decides which verification function runs. RS256 verifies with a <strong>public</strong> key; HS256 verifies with a <strong>shared secret</strong>. The server passes the same key variable to both.',
            'The RSA public key is not secret - it is published at <a href="jwks.php">jwks.php</a> and in <code>keys/public.pem</code>. That is by design for RS256.',
            'If you set <code>alg: HS256</code>, the server calls the HMAC verifier and passes it the public key <em>bytes</em>. You have those bytes.',
            'So: HMAC-SHA256 over <code>header.payload</code> using the exact PEM text of the public key as the secret. Byte-for-byte, including the header/footer lines and the trailing newline.',
            'Workbench &rarr; algorithm <code>HS256 (key = server public key)</code> does exactly this. Set <code>role: admin</code> and sign.',
        ],
        6 => [
            'The <code>kid</code> ("key ID") header is a hint about <em>which</em> key to use. Here it is concatenated straight into a filesystem path.',
            'A key ID is attacker-controlled data. <code>file_get_contents("keys/" . $kid)</code> with no normalisation is a path traversal in a place people forget to look.',
            'You do not need to read a secret file - you need a file whose contents you can <strong>predict exactly</strong>, so you can HMAC with the same bytes.',
            'On Linux, <code>/dev/null</code> reads as the empty string. If the key is <code>""</code>, you can compute <code>HMAC-SHA256(input, "")</code> yourself.',
            'Header: <code>{"alg":"HS256","kid":"../../../../../../dev/null"}</code>, payload with <code>role: admin</code>, signed with an <strong>empty</strong> HMAC secret.',
        ],
        7 => [
            'Same idea as the previous level, different sink: <code>kid</code> is spliced into a SQL query instead of a path.',
            'The query is <code>SELECT secret FROM signing_keys WHERE kid = \'&lt;kid&gt;\'</code> and the first returned column becomes the HMAC key.',
            'You do not want to <em>read</em> a key - you want the query to return a key you chose. A <code>UNION SELECT</code> lets you inject a literal.',
            'Shape: <code>nonexistent\' UNION SELECT \'mykey\'--</code>. Now the verifier HMACs with <code>mykey</code>.',
            'Header <code>{"alg":"HS256","kid":"x\' UNION SELECT \'hackinlab\'-- "}</code>, payload <code>role: admin</code>, HMAC secret <code>hackinlab</code>.',
        ],
        8 => [
            'The <code>jku</code> header is a URL the verifier fetches to get a JSON Web Key Set. Trusting it blindly means the attacker supplies the key.',
            'The allowlist here is <code>strpos($jku, "auth.hackinlab.internal") !== false</code> - it asks "does this substring appear anywhere", not "is this the host".',
            'A URL like <code>http://localhost/paste.php?id=X&amp;pad=auth.hackinlab.internal</code> contains the trusted string in the query, but the host is yours.',
            'Use <a href="paste.php">paste.php</a> to host your own JWKS. The Workbench can generate a keypair and export the matching JWKS for you.',
            'Generate keypair &rarr; publish JWKS to paste.php &rarr; sign an RS256 token with <code>role: admin</code>, <code>kid</code> matching your JWKS, and <code>jku</code> pointing at your paste URL with the allowlist string appended.',
        ],
        9 => [
            'Read the two code blocks carefully. The middleware and the application read <strong>different</strong> claims out of the same token.',
            'Middleware: <code>$claims["role"]</code> must not be <code>admin</code> (defence against forged roles). Application: <code>$claims["user"]["role"] ?? $claims["role"]</code>.',
            'The middleware never looks inside the nested <code>user</code> object, so a nested role passes the guard untouched.',
            'The signature is checked properly here - but you learned the secret in level 4, and this level uses the same weak key.',
            'Payload shape: <code>{"role":"user","user":{"name":"guest","role":"admin"}, ...}</code>, signed with the level-4 secret.',
        ],
        10 => [
            'Two components parse the same payload bytes: a regex WAF and <code>json_decode</code>. Parser differentials live in the gap between them.',
            'The WAF uses <code>preg_match(\'/"role"\\s*:\\s*"([^"]*)"/\', $json, $m)</code>. <code>preg_match</code> returns the <strong>first</strong> match only.',
            'RFC 8259 leaves duplicate object keys undefined. PHP\'s <code>json_decode</code> keeps the <strong>last</strong> occurrence. First vs last is the whole exploit.',
            'So build a payload where <code>role</code> appears twice: harmless first, dangerous last. Note that the Workbench JSON editor sends your raw text, so duplicates survive.',
            'Raw payload: <code>{"sub":"guest","role":"user","role":"admin","exp":9999999999}</code> signed with the level-4 secret. Alternative: escape a letter as <code>\\u0072ole</code> so the regex misses the key entirely.',
        ],
    ];
    return $h[$level] ?? [];
}

/* =========================================================================
 * Shared level UI
 * ===================================================================== */

/** The textarea + submit button every level uses. */
function jwt_token_form(string $issued, string $submitted, string $label = 'Forged token'): string
{
    ob_start(); ?>
    <form method="post" class="jwt-form">
        <div class="form-group">
            <label class="form-label">Token the server issued you</label>
            <textarea class="form-control jwt-ta" rows="3" readonly onclick="this.select()"><?= lk_esc($issued) ?></textarea>
        </div>
        <div class="form-group">
            <label class="form-label"><?= lk_esc($label) ?></label>
            <textarea name="token" class="form-control jwt-ta" rows="4" spellcheck="false"
                      placeholder="paste your token here"><?= lk_esc($submitted) ?></textarea>
        </div>
        <div class="jwt-actions">
            <button class="btn btn-primary" type="submit">Send to /api/profile</button>
            <a class="btn btn-outline" href="tools.php">Open JWT Workbench &rarr;</a>
        </div>
    </form>
    <?php
    return ob_get_clean();
}

/** Rendered decode of whatever the learner sent. */
function jwt_inspect_block(string $token): string
{
    if (trim($token) === '') {
        return '';
    }
    return '<div class="lk-box"><h4><span class="lk-tag">TOKEN</span>What you actually sent</h4>'
         . '<div class="lk-body">' . jwt_debug_table($token) . '</div></div>';
}

/** Standard "authorisation decision" result block. */
function jwt_decision(bool $ok, string $role, string $detail = ''): string
{
    if ($ok) {
        return '<div class="message success"><strong>/api/profile</strong> &rarr; 200 OK, role=<code>'
             . lk_esc($role) . '</code>' . ($detail !== '' ? '<br>' . $detail : '') . '</div>';
    }
    return '<div class="message error"><strong>/api/profile</strong> &rarr; 401 Unauthorized'
         . ($detail !== '' ? '<br>' . $detail : '') . '</div>';
}

/** Shared page furniture: the workbench link and the "no fuzzing" reminder. */
function jwt_extra_head(): string
{
    return '<style>
        .jwt-ta { font-family: "JetBrains Mono", ui-monospace, monospace; font-size: 0.76rem;
                  word-break: break-all; line-height: 1.55; }
        .jwt-actions { display: flex; gap: 0.6rem; flex-wrap: wrap; margin-top: 0.5rem; }
        .jwt-form { margin-bottom: 0.75rem; }
    </style>';
}
