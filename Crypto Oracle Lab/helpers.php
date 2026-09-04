<?php
/**
 * Crypto Oracle Lab · lab metadata, flags, hints and shared level UI.
 */

require_once __DIR__ . '/lab_kit.php';
require_once __DIR__ . '/crypto.php';

function cryptolab(): array
{
    return [
        'slug'    => 'crypto',
        'name'    => 'Crypto Oracle Lab',
        'icon'    => 'AES',
        'total'   => 10,
        'tagline' => 'Strong primitives, wrong constructions',
    ];
}

function crypto_flag(int $level): string
{
    $flags = [
        1  => 'FLAG{encoding_is_not_encryption}',
        2  => 'FLAG{known_plaintext_recovers_the_keystream}',
        3  => 'FLAG{ecb_blocks_are_interchangeable}',
        4  => 'FLAG{one_byte_at_a_time_out_of_ecb}',
        5  => 'FLAG{cbc_gives_you_a_bit_flipping_editor}',
        6  => 'FLAG{padding_errors_decrypt_everything}',
        7  => 'FLAG{sha1_kept_going_where_i_told_it_to}',
        8  => 'FLAG{the_comparison_told_me_when_to_stop}',
        9  => 'FLAG{mt_rand_is_not_a_csprng}',
        10 => 'FLAG{one_nonce_two_messages_zero_secrecy}',
    ];
    return $flags[$level] ?? '';
}

function crypto_levels(): array
{
    return [
        1 => [
            'title'      => 'Encoding Is Not Encryption',
            'difficulty' => 'Easy',
            'skill'      => 'Telling encoding, hashing and encryption apart on sight',
            'desc'       => 'The session token looks random. It is hex. Nothing about it resists being rewritten.',
        ],
        2 => [
            'title'      => 'Repeating-Key XOR',
            'difficulty' => 'Easy',
            'skill'      => 'Known-plaintext recovery, why XOR alone is not a cipher',
            'desc'       => 'A short key XORed over the token. You know the plaintext format, so the key falls out of one subtraction.',
        ],
        3 => [
            'title'      => 'ECB Cut and Paste',
            'difficulty' => 'Medium',
            'skill'      => 'Block alignment, ciphertext rearrangement without the key',
            'desc'       => 'ECB encrypts each block independently, so blocks can be reordered, duplicated and spliced between messages.',
        ],
        4 => [
            'title'      => 'ECB Byte at a Time',
            'difficulty' => 'Medium',
            'skill'      => 'Turning an encryption oracle into a decryption oracle',
            'desc'       => 'The service appends a secret to whatever you submit and encrypts the result. That is enough to read the secret.',
        ],
        5 => [
            'title'      => 'CBC Bit Flipping',
            'difficulty' => 'Medium',
            'skill'      => 'Malleability, and why encryption is not integrity',
            'desc'       => 'Changing one byte of ciphertext changes one byte of the next plaintext block, predictably. No key required.',
        ],
        6 => [
            'title'      => 'Padding Oracle',
            'difficulty' => 'Hard',
            'skill'      => 'One bit of feedback per query, compounded into full decryption',
            'desc'       => 'The endpoint distinguishes "bad padding" from "bad content". That single distinction decrypts the whole message.',
        ],
        7 => [
            'title'      => 'Hash Length Extension',
            'difficulty' => 'Hard',
            'skill'      => 'Merkle-Damgard structure, why H(secret || message) is not a MAC',
            'desc'       => 'A digest is the hash function\'s internal state. Given one, you can keep hashing from where it stopped.',
        ],
        8 => [
            'title'      => 'The Comparison That Talks',
            'difficulty' => 'Hard',
            'skill'      => 'Side channels, measuring rather than guessing',
            'desc'       => 'A byte-by-byte comparison that returns early leaks how much of your guess was right, in the response time.',
        ],
        9 => [
            'title'      => 'Predictable Randomness',
            'difficulty' => 'Expert',
            'skill'      => 'PRNG vs CSPRNG, seed recovery from observed output',
            'desc'       => 'Session tokens come from mt_rand() seeded with the clock. Recover the seed and every token becomes predictable.',
        ],
        10 => [
            'title'      => 'Nonce Reuse',
            'difficulty' => 'Expert',
            'skill'      => 'Stream cipher keystream reuse, forging without the key',
            'desc'       => 'Two messages encrypted under the same CTR nonce. XOR them together and the key cancels out.',
        ],
    ];
}

function crypto_hints(int $level): array
{
    $h = [
        1 => [
            'Before attacking anything, classify it. Encoding is reversible with no key. Hashing is one-way. Encryption needs a key. Which of the three is a string of hex that decodes to readable text?',
            'Paste the token into the Workbench and hit <em>hex decode</em>. If the result is legible, there was never a key involved.',
            'The plaintext is a set of <code>key=value</code> pairs. You can edit it like any other string.',
            'Change <code>role=user</code> to <code>role=admin</code>, re-encode as hex, and submit.',
            'Workbench &rarr; hex decode &rarr; edit &rarr; hex encode &rarr; paste into the token field.',
        ],
        2 => [
            'XOR has one property that defines every attack on it: <code>a XOR b XOR b = a</code>. Encryption and decryption are the same operation.',
            'So if you know a plaintext byte and its ciphertext byte, the key byte is just <code>plain XOR cipher</code>. No searching required.',
            'The level shows you the exact plaintext of your own token. That is a complete known-plaintext pair over the whole message.',
            'XOR the ciphertext with the known plaintext to get the repeating key. The key length is visible as the period at which the recovered bytes repeat.',
            'Recover the key, build the plaintext you want with <code>role=admin</code>, XOR it with the same key, base64url it, submit.',
        ],
        3 => [
            'ECB encrypts each 16-byte block on its own. Same key, same plaintext block, same ciphertext block - every time, in any message.',
            'That means ciphertext blocks are portable. You can take a block produced by one request and paste it into another.',
            'Work out where the block boundaries fall. Count the bytes of the prefix the server puts before your input, then pad your input so the interesting text starts exactly on a boundary.',
            'You need two requests: one that produces a block containing <code>admin</code> plus valid padding, and one whose final block you replace with it.',
            'Craft an email whose bytes place <code>admin</code> + PKCS#7 padding alone in block 1, keep that block, then craft a second email that pushes <code>role=</code> to end exactly at a boundary and swap the last block in.',
        ],
        4 => [
            'The oracle computes <code>ECB(your_input || SECRET)</code>. You control the length of the prefix, so you control where the block boundary cuts the secret.',
            'Send 15 bytes. Block 0 is then <code>AAAAAAAAAAAAAAA</code> plus the first byte of the secret - a single unknown.',
            'Now send 15 bytes plus a guessed 16th byte and compare block 0. When the two ciphertexts match, your guess was right. That is 256 comparisons for one byte, at most.',
            'Repeat with 14 bytes of padding to pull the second secret byte into the same position, and so on. Each recovered byte shortens the next search.',
            'The Workbench has a <em>byte-at-a-time</em> runner: it does exactly this loop against the level oracle and prints each recovered byte with the alignment it used.',
        ],
        5 => [
            'CBC decryption is <code>P[i] = D(C[i]) XOR C[i-1]</code>. Your control over <code>C[i-1]</code> is direct, byte-for-byte, control over <code>P[i]</code>.',
            'So to change plaintext byte <em>n</em> of block <em>i</em> from <code>x</code> to <code>y</code>, XOR byte <em>n</em> of block <em>i-1</em> with <code>x XOR y</code>.',
            'Block <em>i-1</em> itself decrypts to garbage. Pick a target where a corrupted preceding block does not matter - here, the comment field.',
            'The plaintext is exactly two blocks. Block 1 is <code>;role=guest;id=1</code>. You want <code>;role=admin;id=1</code>, so five bytes change.',
            'For each of those five positions <em>n</em>: <code>newC0[n] = C0[n] XOR old[n] XOR new[n]</code>. The Workbench <em>bit-flip calculator</em> does this arithmetic.',
        ],
        6 => [
            'CBC decryption ends with a padding check. If the endpoint reacts differently to bad padding than to good padding with bad content, it has told you something about the plaintext.',
            'Take two blocks <code>C0 C1</code>. Send <code>R C1</code> for a chosen <code>R</code>. The victim block decrypts to <code>D(C1) XOR R</code>. When that ends in valid padding, the oracle says so.',
            'Try all 256 values of <code>R[15]</code>. One (occasionally two) will produce valid padding, almost always <code>0x01</code>. That gives you <code>D(C1)[15] = R[15] XOR 0x01</code>.',
            'With <code>D(C1)[15]</code> known, set <code>R[15]</code> so the last byte decrypts to <code>0x02</code>, and search <code>R[14]</code> for the next valid padding. Repeat leftwards; then <code>P[i] = D(C[i]) XOR C[i-1]</code>.',
            'The level exposes <code>oracle.php</code>, which answers one query with padding-ok or padding-bad. Script the loop against it, or use the Workbench runner. 256 x 16 queries per block, worst case.',
        ],
        7 => [
            'SHA-1 is Merkle-Damgard: it absorbs 64-byte chunks into a 160-bit state, and the final state <em>is</em> the digest. Nothing is discarded at the end.',
            'So a digest is a resumable checkpoint. Load those five registers back in and you can keep hashing as though you had the original message.',
            'You do not know the secret, but you do not need it - you only need its <strong>length</strong>, to reproduce the padding SHA-1 appended after <code>secret || data</code>.',
            'Your forged message is <code>data || glue_padding || your_suffix</code>, where the glue is <code>0x80</code>, zeros, and the 64-bit bit-length of <code>secret || data</code>.',
            'Brute force the secret length from 1 to 32 (the Workbench does this), append <code>&amp;role=admin</code>, and submit the extended data with the recomputed MAC.',
        ],
        8 => [
            'Look at the comparison loop. It returns as soon as two bytes differ, so its running time is proportional to the length of the matching prefix.',
            'That turns "is this token correct?" into "how many leading bytes of this token are correct?" - a completely different, and much easier, question.',
            'Fix every byte but the first. Try all 16 hex values for byte 0, timing each. The value with the highest median time is the correct one.',
            'Use the <strong>median</strong> of several samples per candidate, not one measurement. Network jitter is noise; the signal is a consistent step of a few milliseconds.',
            'The Workbench <em>timing harness</em> runs this attack against the level endpoint and prints a per-candidate timing table so you can see the winning byte stand out.',
        ],
        9 => [
            '<code>mt_rand()</code> is a Mersenne Twister: fast, uniform, and completely deterministic given its seed. It is a statistical generator, not a cryptographic one.',
            'Seeding it with <code>time()</code> means the whole key space is "which second was it" - typically a few hundred candidates.',
            'The level tells you the window in which the admin token was issued. Every second in that window is one candidate seed.',
            'For each candidate: <code>mt_srand($t)</code>, generate the token the same way the server does, and compare with a token you were issued at a known time to confirm the algorithm before attacking the admin one.',
            'The Workbench <em>seed cracker</em> takes an observed token plus a time window and returns the matching seed; from there, generate the admin token directly.',
        ],
        10 => [
            'CTR turns a block cipher into a stream cipher: <code>C = P XOR keystream(key, nonce)</code>. The keystream depends only on the key and the nonce.',
            'Reuse the nonce and two messages share a keystream. XOR the two ciphertexts and the keystream cancels: <code>C1 XOR C2 = P1 XOR P2</code>.',
            'Here you have a known plaintext for one message, so you can go further: <code>keystream = C1 XOR P1</code>, in full, for as many bytes as you have.',
            'With the keystream in hand you can decrypt the other message - and, more usefully, encrypt any plaintext of your own.',
            'Recover the keystream from your own token, build the session string with <code>role=admin</code>, XOR it with the keystream, and submit.',
        ],
    ];
    return $h[$level] ?? [];
}

/* =========================================================================
 * Shared UI
 * ===================================================================== */

function crypto_extra_head(): string
{
    return '<style>
        .cl-mono { font-family: "JetBrains Mono", ui-monospace, monospace; font-size: 0.76rem;
                   word-break: break-all; line-height: 1.55; }
        .cl-actions { display: flex; gap: 0.6rem; flex-wrap: wrap; margin-top: 0.5rem; }
    </style>';
}

/** The token textarea most levels use. */
function crypto_token_form(string $issued, string $submitted, string $label = 'Forged token', string $btn = 'Send to /api/session'): string
{
    ob_start(); ?>
    <form method="post">
        <div class="form-group">
            <label class="form-label">Token the server issued you</label>
            <textarea class="form-control cl-mono" rows="3" readonly onclick="this.select()"><?= lk_esc($issued) ?></textarea>
        </div>
        <div class="form-group">
            <label class="form-label"><?= lk_esc($label) ?></label>
            <textarea name="token" class="form-control cl-mono" rows="3" spellcheck="false"><?= lk_esc($submitted) ?></textarea>
        </div>
        <div class="cl-actions">
            <button class="btn btn-primary" type="submit"><?= lk_esc($btn) ?></button>
            <a class="btn btn-outline" href="tools.php">Open Crypto Workbench &rarr;</a>
        </div>
    </form>
    <?php
    return ob_get_clean();
}

/** A single-answer form, for levels where the goal is to recover a value. */
function crypto_answer_form(string $label, string $value, string $placeholder = ''): string
{
    ob_start(); ?>
    <form method="post">
        <div class="form-group">
            <label class="form-label"><?= lk_esc($label) ?></label>
            <input type="text" name="answer" class="form-control cl-mono" spellcheck="false" autocomplete="off"
                   placeholder="<?= lk_esc($placeholder) ?>" value="<?= lk_esc($value) ?>">
        </div>
        <div class="cl-actions">
            <button class="btn btn-primary" type="submit">Submit</button>
            <a class="btn btn-outline" href="tools.php">Open Crypto Workbench &rarr;</a>
        </div>
    </form>
    <?php
    return ob_get_clean();
}

function crypto_decision(bool $ok, string $detail): string
{
    return $ok
        ? '<div class="message success"><strong>/api/session</strong> &rarr; 200 OK<br>' . $detail . '</div>'
        : '<div class="message error"><strong>/api/session</strong> &rarr; 401<br>' . $detail . '</div>';
}

/** Parse the `k=v;k=v` session strings the lab uses. */
function crypto_parse_kv(string $s): array
{
    $out = [];
    foreach (preg_split('/[;&]/', $s) as $pair) {
        if ($pair === '') {
            continue;
        }
        $bits = explode('=', $pair, 2);
        if (count($bits) === 2) {
            $out[trim($bits[0])] = $bits[1];
        }
    }
    return $out;
}
