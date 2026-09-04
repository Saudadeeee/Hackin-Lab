<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/secrets.php';

$L    = 7;
$meta = crypto_levels()[$L];

$issuedData = 'user=guest&role=user&id=41';
$issuedMac  = sha1(cl_secret_l7() . $issuedData);

$data = (string)($_POST['data'] ?? '');
$mac  = trim((string)($_POST['mac'] ?? ''));

$flag     = '';
$result   = '';
$pipeline = [];

if ($data !== '' || $mac !== '') {
    $expected = sha1(cl_secret_l7() . $data);
    $valid    = hash_equals($expected, strtolower($mac));
    $params   = crypto_parse_kv($data);
    $role     = $params['role'] ?? '';

    $pipeline = [
        ['label' => 'data as submitted', 'value' => $data],
        ['label' => 'sha1(SECRET . $data)', 'value' => $expected,
         'note'  => 'The server recomputes the tag over the whole string. It has no way to tell which part you
                     supplied.'],
        ['label' => 'hash_equals(expected, given)', 'value' => $valid ? 'tag accepted' : 'tag rejected',
         'verdict' => $valid ? 'pass' : 'block'],
        ['label' => 'parse_kv($data) — later values win', 'value' => json_encode($params)],
        ['label' => '$params["role"]', 'value' => (string)$role, 'verdict' => $role === 'admin' ? 'pass' : null],
    ];

    if (!$valid) {
        $result = crypto_decision(false, 'MAC does not match.');
    } elseif ($role === 'admin') {
        $flag   = crypto_flag($L);
        $result = crypto_decision(true, 'Request authenticated as <code>role=admin</code>.');
    } else {
        $result = crypto_decision(true, 'Authenticated as <code>' . lk_esc($role) . '</code>.');
    }
}

$code = <<<'PHP'
// "Signed" API requests: the secret is prepended to the data and hashed.
define('API_SECRET', '**************');       // length not disclosed

function sign(string $data): string {
    return sha1(API_SECRET . $data);          // <- a hash, not a MAC
}

function handle(string $data, string $mac) {
    if (!hash_equals(sign($data), $mac)) {
        return deny('bad signature');
    }
    $p = parse_query($data);                  // later duplicates win
    if (($p['role'] ?? '') === 'admin') {
        grant_admin();
    }
}
PHP;

$fixBad = <<<'PHP'
return sha1(API_SECRET . $data);
PHP;

$fixGood = <<<'PHP'
// HMAC exists precisely because H(secret || message) is forgeable. Its
// two-pass construction (inner and outer keyed hashes) makes the digest
// useless as a resumable state.
return hash_hmac('sha256', $data, API_SECRET);

// Verify with a constant-time comparison:
if (!hash_equals(hash_hmac('sha256', $data, API_SECRET), $given)) {
    return deny('bad signature');
}

// Also worth fixing: parse the parameters ONCE, and reject duplicate keys
// rather than letting "later wins" decide an authorisation value.
PHP;

lk_page([
    'lab'        => cryptolab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => crypto_extra_head(),

    'code'       => $code,
    'vuln_lines' => [5, 6],
    'annotation' => 'SHA-1 is a Merkle-Damgard hash: its output <em>is</em> its internal state after the last
        block. Given <code>sha1(secret || data)</code>, an attacker can resume the computation and append data
        without knowing the secret.',

    'theory' => '<p>A Merkle-Damgard hash processes the message in 64-byte chunks, folding each into a fixed-size
        state, and returns that state as the digest. Nothing is truncated or discarded, so the digest is a complete
        checkpoint of the computation.</p>
        <p>An attacker who holds <code>H(secret || data)</code> can therefore initialise the compression function
        with those registers and continue as if they had just processed <code>secret || data</code>. What they
        <em>cannot</em> skip is the padding the hash appended before finishing - the <code>0x80</code>, the zeros,
        and the 64-bit length. So that padding becomes part of the forged message, sitting between the original data
        and the appended suffix.</p>
        <p>Two consequences worth remembering. First, the attack needs the <strong>length</strong> of the secret,
        not the secret; 32 guesses usually covers it. Second, it only works when the appended junk is tolerated by
        the parser - which is why "later duplicates win" query-string parsing turns a curiosity into a
        privilege escalation. SHA-256 has the same structure and the same weakness; SHA-3 and BLAKE2 do not.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The rule is short: never build a MAC out of a bare hash. Use HMAC, or an AEAD, or a signature
            scheme - all of which are designed for exactly this job.',
    ],

    'scenario' => '<strong>Scenario:</strong> an API authenticates requests with <code>sha1(SECRET . data)</code>.
        You hold one valid pair. The parameter parser lets later duplicates override earlier ones.
        <br><strong>Goal:</strong> submit data ending in <code>&amp;role=admin</code> with a MAC the server accepts.',

    'model' => [
        'title' => 'What you have to construct',
        'html'  => '<pre class="lk-sinkline">server hashed:  SECRET || data
your forgery:            data || glue || suffix
server will hash: SECRET || data || glue || suffix</pre>
        <p>where <code>glue</code> is the padding SHA-1 appended to <code>SECRET || data</code>:
        <code>0x80</code>, then zeros, then the length of <code>SECRET || data</code> in <strong>bits</strong> as a
        64-bit big-endian integer.</p>
        <table class="lk-kv">
            <tr><td>known</td><td>data (' . strlen($issuedData) . ' bytes), its MAC</td></tr>
            <tr><td>unknown</td><td>SECRET, and its length</td></tr>
            <tr><td>guessed</td><td>the length, 1..32 - one request each</td></tr>
        </table>
        <p>The glue contains raw bytes, so the <code>data</code> field must be sent URL-encoded (<code>%80</code>,
        <code>%00</code>, and so on). The Workbench <em>length-extension</em> tool takes the original data, the MAC,
        your suffix and a length guess, and returns the encoded data plus the new MAC.</p>',
    ],

    'form' => '<div class="lk-box"><h4><span class="lk-tag">CAPTURED</span>A valid signed request</h4><div class="lk-body">
            <table class="lk-kv">
                <tr><td>data</td><td>' . lk_esc($issuedData) . '</td></tr>
                <tr><td>mac</td><td>' . $issuedMac . '</td></tr>
            </table></div></div>
        <form method="post">
            <div class="form-group">
                <label class="form-label">data (URL-encoded; raw bytes allowed)</label>
                <textarea name="data" class="form-control cl-mono" rows="3" spellcheck="false">' . lk_esc($data) . '</textarea>
            </div>
            <div class="form-group">
                <label class="form-label">mac</label>
                <input type="text" name="mac" class="form-control cl-mono" spellcheck="false" value="' . lk_esc($mac) . '">
            </div>
            <div class="cl-actions">
                <button class="btn btn-primary" type="submit">Send signed request</button>
                <a class="btn btn-outline" href="tools.php">Open Crypto Workbench &rarr;</a>
            </div>
        </form>',

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'You extended a hash you could not compute, over a secret you never saw.',
    'why'      => '<p>The server recomputed <code>sha1(SECRET . data)</code> over your extended data and got your
        tag, because your tag was produced by the same computation - resumed from the checkpoint the original tag
        handed you.</p>
        <p>The glue padding is visible in trace step 1 as a run of control bytes in the middle of the query string.
        The parser skipped over it as an unrecognised parameter and then read your <code>role=admin</code> as the
        final value.</p>',

    'pipeline' => $pipeline,
    'hints'    => crypto_hints($L),
]);
