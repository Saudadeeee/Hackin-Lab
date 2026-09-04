<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/secrets.php';

$L    = 4;
$meta = crypto_levels()[$L];
$key  = cl_key(4);

$probe  = (string)($_POST['probe'] ?? 'AAAAAAAAAAAAAAA');
$answer = trim((string)($_POST['answer'] ?? ''));

$flag     = '';
$result   = '';
$pipeline = [];
$oracle   = '';

if (isset($_POST['probe'])) {
    $ct = cl_aes_ecb_encrypt($probe . cl_secret_l4(), $key);
    $oracle = '<div class="lk-box"><h4><span class="lk-tag">ORACLE</span>ECB(your_input || SECRET)</h4><div class="lk-body">'
        . '<table class="lk-kv">'
        . '<tr><td>your input</td><td>' . strlen($probe) . ' bytes</td></tr>'
        . '<tr><td>ciphertext</td><td>' . strlen($ct) . ' bytes / ' . (strlen($ct) / 16) . ' blocks</td></tr>'
        . '</table>' . cl_block_table($ct)
        . '<p class="text-muted" style="margin-top:0.5rem">Watch the ciphertext length as you add one byte at a time. '
        . 'The step where it jumps by 16 tells you the secret\'s length modulo the block size.</p>'
        . '</div></div>';
}

if ($answer !== '') {
    $ok = hash_equals(cl_secret_l4(), $answer);
    $pipeline = [
        ['label' => 'your recovered plaintext', 'value' => $answer],
        ['label' => 'strcmp against the appended secret', 'value' => $ok ? 'identical' : 'differs',
         'verdict' => $ok ? 'pass' : 'block'],
    ];
    if ($ok) {
        $flag   = crypto_flag($L);
        $result = '<div class="message success">Recovered. The oracle only ever encrypted - you turned it into a
            decryptor.</div>';
    } else {
        $result = '<div class="message error">Not the secret. Compare your recovered prefix with the block table
            above: the first byte you get wrong invalidates everything after it.</div>';
    }
}

$code = <<<'PHP'
// A "safe" encryption service: it never decrypts anything for you, and your
// input is only ever a prefix.
function encrypt_with_note(string $userInput): string {
    $plain = $userInput . SECRET_NOTE;          // secret appended, not mixed
    return bin2hex(aes_128_ecb_encrypt($plain, $key));
}

// Exposed as:  GET oracle.php?level=4&prefix=<hex>
PHP;

$fixBad = <<<'PHP'
$plain = $userInput . SECRET_NOTE;
return aes_128_ecb_encrypt($plain, $key);          // ECB: block i is E(P[i])
PHP;

$fixGood = <<<'PHP'
// Do not concatenate a secret with attacker data before encrypting, and do
// not use ECB. With a random nonce and an AEAD, the same input encrypted
// twice produces unrelated ciphertexts, so no comparison oracle exists.
$nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
return $nonce . sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
    $userInput, '', $nonce, $key
);
// The secret note is not the client's business at all - keep it server-side
// and reference it by id.
PHP;

lk_page([
    'lab'        => cryptolab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => crypto_extra_head(),

    'code'       => $code,
    'vuln_lines' => [4, 5],
    'annotation' => 'The service only encrypts, and only ever appends the secret after your input. Under ECB that
        is sufficient to read the secret one byte at a time, because you control exactly where the block boundary
        cuts it.',

    'theory' => '<p>An encryption oracle looks harmless: it never reveals a key and never decrypts. Under ECB it is
        a decryption oracle anyway, because ECB lets you <em>compare</em> ciphertext blocks and comparison is all
        you need.</p>
        <p>The technique generalises to any deterministic transformation you can query with a chosen prefix. The
        pattern to recognise is: attacker-controlled length + deterministic output + a boundary you can slide. The
        same shape appears in compression side channels (CRIME, BREACH), where the observable is length rather than
        block equality.</p>
        <p>Note also the free reconnaissance: adding one byte at a time and watching for the moment the ciphertext
        grows by a block tells you the secret\'s length, before you recover a single byte of it.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Randomised encryption removes the oracle entirely: without determinism there is nothing to
            compare, so the byte-at-a-time loop has no signal to follow.',
    ],

    'scenario' => '<strong>Scenario:</strong> <code>oracle.php?level=4&amp;prefix=&lt;hex&gt;</code> returns
        <code>ECB(prefix || SECRET)</code> as hex. It is happy to answer as many times as you like.
        <br><strong>Goal:</strong> recover <code>SECRET</code> and submit it.',

    'model' => [
        'title' => 'The loop, stated precisely',
        'html'  => '<p>Write <code>S</code> for the secret and <code>A</code> for a filler byte.</p>
        <ol>
            <li>Send 15 filler bytes. Block 0 of the reply is <code>E(AAAAAAAAAAAAAAA || S[0])</code> - one unknown.</li>
            <li>For each candidate byte <code>c</code> in 0..255, send <code>AAAAAAAAAAAAAAA || c</code> and keep
                block 0. When it equals the block from step 1, <code>c == S[0]</code>.</li>
            <li>Now send 14 filler bytes, so block 0 becomes <code>E(AAAAAAAAAAAAAA || S[0] || S[1])</code>. You know
                <code>S[0]</code>, so the same comparison recovers <code>S[1]</code>.</li>
            <li>Continue. After 16 bytes, slide to block 1 by keeping the filler at
                <code>15 - (i mod 16)</code> and comparing block <code>floor(i/16)</code>.</li>
        </ol>
        <p>Cost: at most 256 queries per byte, and typically far fewer if you try printable ASCII first. Compare
        that with brute-forcing the secret as a whole - the difference between linear and exponential is the entire
        lesson.</p>
        <p>The Workbench has a runner that performs this loop against the endpoint and prints each byte as it lands,
        along with the alignment it used.</p>',
    ],

    'form' => '<form method="post" style="margin-bottom:1rem">
            <div class="form-group">
                <label class="form-label">Query the oracle by hand (your input, as text)</label>
                <input type="text" name="probe" class="form-control cl-mono" spellcheck="false" value="' . lk_esc($probe) . '">
            </div>
            <button class="btn btn-outline" type="submit">Encrypt</button>
        </form>'
        . crypto_answer_form('Recovered secret', $answer, 'the exact plaintext that was appended'),

    'result'   => $oracle . $result,
    'flag'     => $flag,
    'flag_msg' => 'An encrypt-only service gave up its secret.',
    'why'      => '<p>You never decrypted anything. You arranged for a block whose contents were entirely known
        except for one byte, then encrypted all 256 possibilities and looked for the match. ECB guarantees the match
        is exact, because the same plaintext block always produces the same ciphertext block.</p>
        <p>Each recovered byte made the next one easier, which is why the cost is linear in the secret\'s length
        rather than exponential.</p>',

    'pipeline' => $pipeline,
    'hints'    => crypto_hints($L),
]);
