<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/secrets.php';

$L    = 6;
$meta = crypto_levels()[$L];
$key  = cl_key(6);
$iv   = cl_iv(6);

$captured = cl_hex($iv . cl_aes_cbc_encrypt(cl_secret_l6(), $key, $iv));

$probe  = trim((string)($_POST['probe'] ?? ''));
$answer = trim((string)($_POST['answer'] ?? ''));

$flag     = '';
$result   = '';
$pipeline = [];
$probeOut = '';

if ($probe !== '') {
    $blob = cl_unhex($probe);
    if (strlen($blob) < 32 || strlen($blob) % 16 !== 0) {
        $probeOut = '<div class="message error">malformed &mdash; expected IV plus whole blocks</div>';
    } else {
        $p  = cl_pkcs7_unpad(cl_aes_cbc_decrypt_raw(substr($blob, 16), $key, substr($blob, 0, 16)));
        $ok = $p !== null;
        $probeOut = '<div class="message ' . ($ok ? 'success' : 'error') . '">oracle says: <code>'
            . ($ok ? 'padding-ok' : 'padding-bad') . '</code></div>'
            . '<p class="text-muted">That is the entire response. No plaintext, no error detail &mdash; one bit.</p>';
    }
}

if ($answer !== '') {
    $ok = hash_equals(cl_secret_l6(), $answer);
    $pipeline = [
        ['label' => 'your recovered plaintext', 'value' => $answer],
        ['label' => 'compare with the encrypted message', 'value' => $ok ? 'identical' : 'differs',
         'verdict' => $ok ? 'pass' : 'block'],
    ];
    if ($ok) {
        $flag   = crypto_flag($L);
        $result = '<div class="message success">Decrypted, using nothing but yes/no answers about padding.</div>';
    } else {
        $result = '<div class="message error">Not the plaintext. Recover left to right within each block, and
            remember the final block still carries its PKCS#7 padding.</div>';
    }
}

$code = <<<'PHP'
// POST /api/message  - decrypts a message and reports what went wrong.
function read_message(string $blob): string {
    $iv     = substr($blob, 0, 16);
    $plain  = pkcs7_unpad(aes_128_cbc_decrypt(substr($blob, 16), $key, $iv));

    if ($plain === null) {
        return 'padding-bad';        // <- distinguishable failure
    }
    if (!valid_message($plain)) {
        return 'padding-ok';         // decrypted fine, content rejected
    }
    return process($plain);
}
PHP;

$fixBad = <<<'PHP'
$plain = pkcs7_unpad(aes_128_cbc_decrypt($ct, $key, $iv));
if ($plain === null) return 'padding-bad';
if (!valid_message($plain)) return 'padding-ok';
PHP;

$fixGood = <<<'PHP'
// 1. Authenticate first. A ciphertext that fails the MAC is never decrypted,
//    so no padding check ever runs on attacker-chosen data.
if (!hash_equals(hash_hmac('sha256', $ct, $macKey, true), $tag)) {
    return 'invalid';               // ONE failure mode, always
}
$plain = pkcs7_unpad(aes_128_cbc_decrypt($ct, $key, $iv));

// 2. Or drop the hand-rolled construction entirely:
$plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ct, '', $nonce, $key);
if ($plain === false) { return 'invalid'; }

// Note that merging the error MESSAGES is not enough - the timing and the
// response length must be identical too, or the oracle survives.
PHP;

lk_page([
    'lab'        => cryptolab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => crypto_extra_head(),

    'code'       => $code,
    'vuln_lines' => [6, 7, 10],
    'annotation' => 'The endpoint answers two different ways: padding failed, or padding succeeded and the content
        was wrong. That distinction is one bit of information about the decrypted plaintext, and one bit per query
        is enough to recover all of it.',

    'theory' => '<p>Recovering the last byte of a block takes at most 256 queries. Repeat for each of 16 positions
        and you have <code>D(C[i])</code> - the block cipher output before the CBC XOR. Since
        <code>P[i] = D(C[i]) XOR C[i-1]</code> and you hold <code>C[i-1]</code>, the plaintext follows.</p>
        <p>Nothing about AES is weakened here. The attacker learns the intermediate value one byte at a time
        because the server volunteers whether a chosen ciphertext decrypted to something ending in valid padding.
        The cipher is fine; the protocol around it leaks.</p>
        <p>This is the canonical argument for authenticated encryption and for <em>encrypt-then-MAC</em> ordering.
        Verifying the MAC before decrypting means an attacker-modified ciphertext is discarded before any padding
        logic runs, so there is no oracle to query. Historically this bug sank TLS CBC suites (Lucky Thirteen),
        ASP.NET view state, and Ruby on Rails cookies - always the protocol, never the cipher.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Watch for the subtler oracles: a padding failure that returns 3 milliseconds sooner, or a
            response body two bytes shorter, is the same vulnerability with a quieter signal.',
    ],

    'scenario' => '<strong>Scenario:</strong> you captured an encrypted message in transit. The endpoint
        <code>oracle.php?level=6&amp;ct=&lt;hex&gt;</code> tells you whether a ciphertext you submit has valid
        padding.
        <br><strong>Goal:</strong> recover the plaintext and submit it.',

    'model' => [
        'title' => 'One block, from the right',
        'html'  => '<p>Attack a pair <code>C[i-1] C[i]</code>. Replace <code>C[i-1]</code> with a block
        <code>R</code> you choose; the server computes <code>P\' = D(C[i]) XOR R</code>.</p>
        <ol>
            <li>Vary <code>R[15]</code> over 0..255 until the oracle says <code>padding-ok</code>. Then
                <code>P\'[15] = 0x01</code>, so <code>D(C[i])[15] = R[15] XOR 0x01</code>.
                <em>Edge case:</em> you may instead have hit <code>0x02 0x02</code>; disambiguate by changing
                <code>R[14]</code> and re-testing.</li>
            <li>Set <code>R[15] = D(C[i])[15] XOR 0x02</code> so the last byte decrypts to <code>0x02</code>, then
                vary <code>R[14]</code> for the next <code>padding-ok</code>. That gives
                <code>D(C[i])[14] = R[14] XOR 0x02</code>.</li>
            <li>Continue leftwards with target padding <code>0x03</code>, <code>0x04</code>, and so on.</li>
            <li>Finally <code>P[i] = D(C[i]) XOR C[i-1]</code>, using the <em>real</em> previous block.</li>
        </ol>
        <p>Budget: 128 queries per byte on average, so roughly 2,000 per block. Script it against the oracle URL, or
        use the Workbench runner which prints each byte with the query count it cost.</p>',
    ],

    'form' => '<div class="lk-box"><h4><span class="lk-tag">CAPTURED</span>Ciphertext (IV || blocks, hex)</h4>
        <div class="lk-body">
            <textarea class="form-control cl-mono" rows="3" readonly onclick="this.select()">' . $captured . '</textarea>
            <p class="text-muted" style="margin-top:0.4rem">'
            . (strlen(cl_unhex($captured)) / 16) . ' blocks including the IV.</p>
        </div></div>
        <form method="post" style="margin-bottom:1rem">
            <div class="form-group">
                <label class="form-label">Send one ciphertext to the padding oracle (hex, IV first)</label>
                <textarea name="probe" class="form-control cl-mono" rows="3" spellcheck="false">' . lk_esc($probe) . '</textarea>
            </div>
            <button class="btn btn-outline" type="submit">Ask the oracle</button>
        </form>' . $probeOut
        . crypto_answer_form('Recovered plaintext', $answer, 'the full decrypted message'),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'Full plaintext recovery from a single bit of feedback per query.',
    'why'      => '<p>Each <code>padding-ok</code> answer pinned down one byte of <code>D(C[i])</code> exactly,
        because you had arranged the other bytes so that only one padding length was possible. Sixteen of those
        answers give you the whole block, and the CBC equation converts it to plaintext.</p>
        <p>The server never returned plaintext and never leaked the key. It answered a question about
        <em>well-formedness</em>, and well-formedness depended on the secret.</p>',

    'pipeline' => $pipeline,
    'hints'    => crypto_hints($L),
]);
