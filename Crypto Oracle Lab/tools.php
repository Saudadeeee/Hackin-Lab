<?php
/**
 * Crypto Workbench.
 *
 * The attacks in this lab are arithmetic plus a loop. Doing that arithmetic by
 * hand once is instructive; doing it sixteen times is not. These tools remove
 * the tedium and print their intermediate values, so the method stays visible.
 */
require_once __DIR__ . '/helpers.php';

$action = (string)($_POST['action'] ?? '');
$out    = '';

/** Fetch an oracle response over HTTP from inside the container. */
function wb_oracle(string $query): string
{
    $ctx = stream_context_create(['http' => ['timeout' => 20, 'ignore_errors' => true]]);
    return trim((string)@file_get_contents('http://localhost/oracle.php?' . $query, false, $ctx));
}

function wb_box(string $tag, string $title, string $body): string
{
    return '<div class="lk-box"><h4><span class="lk-tag">' . lk_esc($tag) . '</span>' . lk_esc($title)
         . '</h4><div class="lk-body">' . $body . '</div></div>';
}

switch ($action) {

    /* ------------------------------------------------------------ encoding */
    case 'encode': {
        $v    = (string)($_POST['value'] ?? '');
        $mode = (string)($_POST['mode'] ?? 'hex-enc');
        $r = match ($mode) {
            'hex-enc' => cl_hex($v),
            'hex-dec' => cl_unhex($v),
            'b64-enc' => cl_b64($v),
            'b64-dec' => cl_unb64($v),
            default   => '',
        };
        $out = wb_box('ENCODE', $mode, '<div class="output-box">' . lk_visible($r, 4000) . '</div>');
        break;
    }

    /* ------------------------------------------------------------ xor */
    case 'xor': {
        $a = cl_unhex((string)($_POST['a'] ?? ''));
        $b = (string)($_POST['b'] ?? '');
        $b = ($_POST['b_is_text'] ?? '') === '1' ? $b : cl_unhex($b);
        $r = cl_xor($a, $b);
        $out = wb_box('XOR', 'a XOR b', '<table class="lk-kv">'
            . '<tr><td>a (' . strlen($a) . ' B)</td><td>' . cl_hex($a) . '</td></tr>'
            . '<tr><td>b (' . strlen($b) . ' B)</td><td>' . cl_hex($b) . '</td></tr>'
            . '<tr><td>result hex</td><td>' . cl_hex($r) . '</td></tr>'
            . '<tr><td>result text</td><td>' . lk_visible($r, 2000) . '</td></tr></table>'
            . '<p class="text-muted">If b was a known plaintext, the result is the keystream. Look for a repeating
               period in the hex - that period is the key length.</p>');
        break;
    }

    /* ------------------------------------------------------------ blocks */
    case 'blocks': {
        $c = cl_unhex((string)($_POST['ct'] ?? ''));
        $out = wb_box('BLOCKS', strlen($c) . ' bytes, ' . (int)ceil(strlen($c) / 16) . ' blocks of 16',
            cl_block_table($c)
            . '<p class="text-muted">' . (cl_has_repeated_block($c)
                ? 'Repeated blocks present. Under a mode with chaining or a fresh nonce this is essentially
                   impossible, so this is an ECB fingerprint.'
                : 'No repeated blocks. That does not rule ECB out - it only means the plaintext had no repeated
                   16-byte-aligned chunks.') . '</p>');
        break;
    }

    /* ------------------------------------------------------------ cbc flip */
    case 'cbcflip': {
        $blob   = cl_unhex((string)($_POST['token'] ?? ''));
        $blockN = max(0, (int)($_POST['block'] ?? 1));
        $cur    = (string)($_POST['current'] ?? '');
        $want   = (string)($_POST['target'] ?? '');
        $hasIv  = ($_POST['has_iv'] ?? '1') === '1';

        // Ciphertext block that feeds the target block is the one before it.
        $offset = ($hasIv ? 16 : 0) + ($blockN - 1) * 16;
        if ($blockN === 0) {
            $offset = 0;                        // editing block 0 means editing the IV
        }
        if ($blob === '' || $offset < 0 || $offset + 16 > strlen($blob)) {
            $out = '<div class="message error">Offset falls outside the token. Check the block index and whether an
                IV is prepended.</div>';
            break;
        }
        $edited = $blob;
        $rows   = '';
        for ($i = 0; $i < min(strlen($cur), strlen($want)); $i++) {
            if ($cur[$i] === $want[$i]) {
                continue;
            }
            $old = ord($edited[$offset + $i]);
            $new = $old ^ ord($cur[$i]) ^ ord($want[$i]);
            $edited[$offset + $i] = chr($new);
            $rows .= '<tr><td>byte ' . $i . '</td><td>' . sprintf('%02x', $old) . ' XOR '
                  . sprintf('%02x', ord($cur[$i])) . ' XOR ' . sprintf('%02x', ord($want[$i]))
                  . ' = ' . sprintf('%02x', $new) . '</td></tr>';
        }
        $out = wb_box('CBC FLIP', 'edited ' . ($blockN === 0 ? 'IV' : 'ciphertext block ' . ($blockN - 1)),
            '<table class="lk-kv">' . ($rows ?: '<tr><td colspan="2">no differing bytes</td></tr>') . '</table>'
            . '<div class="form-group" style="margin-top:0.6rem"><label class="form-label">edited token (hex)</label>'
            . '<textarea class="form-control cl-mono" rows="3" onclick="this.select()">' . cl_hex($edited) . '</textarea></div>');
        break;
    }

    /* ------------------------------------------------------------ ECB byte-at-a-time */
    case 'ecb': {
        $secret  = '';
        $queries = 0;
        $alpha   = array_merge(range(32, 126), [10, 13, 0]);   // printable first
        $log     = '';

        for ($i = 0; $i < 64; $i++) {
            $padLen  = 15 - ($i % 16);
            $blockNo = intdiv($i, 16);
            $pad     = str_repeat('A', $padLen);
            $target  = wb_oracle('level=4&prefix=' . bin2hex($pad));
            $queries++;
            $targetBlock = substr(cl_unhex($target), $blockNo * 16, 16);
            if ($targetBlock === '' || strlen($targetBlock) < 16) {
                break;
            }
            $found = null;
            foreach ($alpha as $b) {
                $guess = $pad . $secret . chr($b);
                $resp  = wb_oracle('level=4&prefix=' . bin2hex($guess));
                $queries++;
                if (substr(cl_unhex($resp), $blockNo * 16, 16) === $targetBlock) {
                    $found = chr($b);
                    break;
                }
            }
            if ($found === null) {
                $log .= '<tr><td>byte ' . $i . '</td><td>no match - end of secret (the padding byte changed as the
                    prefix grew)</td></tr>';
                break;
            }
            $secret .= $found;
            $log .= '<tr><td>byte ' . $i . '</td><td>pad=' . $padLen . ' block=' . $blockNo
                 . ' &rarr; <code>' . lk_esc($found) . '</code></td></tr>';
        }
        $out = wb_box('ECB RUNNER', 'byte-at-a-time against oracle.php?level=4',
            '<div class="output-box">' . lk_visible($secret, 2000) . '</div>'
            . '<table class="lk-kv">' . $log . '</table>'
            . '<p class="text-muted">' . $queries . ' oracle queries. Brute-forcing a '
            . strlen($secret) . '-byte secret directly would be 256^' . strlen($secret) . '.</p>');
        break;
    }

    /* ------------------------------------------------------------ padding oracle */
    case 'padding': {
        $blob = cl_unhex((string)($_POST['ct'] ?? ''));
        if (strlen($blob) < 32 || strlen($blob) % 16 !== 0) {
            $out = '<div class="message error">Expected IV followed by whole 16-byte blocks.</div>';
            break;
        }
        $blocks  = cl_blocks($blob);
        $plain   = '';
        $queries = 0;

        for ($bi = 1; $bi < count($blocks); $bi++) {
            $target = $blocks[$bi];
            $prev   = $blocks[$bi - 1];
            $inter  = str_repeat("\x00", 16);      // D(target)

            for ($pos = 15; $pos >= 0; $pos--) {
                $padVal = 16 - $pos;
                $found  = null;
                for ($g = 0; $g < 256; $g++) {
                    $r = str_repeat("\x00", 16);
                    for ($k = $pos + 1; $k < 16; $k++) {
                        $r[$k] = chr(ord($inter[$k]) ^ $padVal);
                    }
                    $r[$pos] = chr($g);
                    $queries++;
                    if (wb_oracle('level=6&ct=' . bin2hex($r . $target)) === 'padding-ok') {
                        // Guard against the 0x02 0x02 ambiguity on the last byte.
                        if ($pos === 15) {
                            $r2 = $r;
                            $r2[14] = chr(ord($r2[14]) ^ 0xff);
                            $queries++;
                            if (wb_oracle('level=6&ct=' . bin2hex($r2 . $target)) !== 'padding-ok') {
                                continue;
                            }
                        }
                        $found = $g;
                        break;
                    }
                }
                if ($found === null) {
                    break 2;
                }
                $inter[$pos] = chr($found ^ $padVal);
            }
            $plain .= cl_xor($inter, $prev);
        }
        $out = wb_box('PADDING ORACLE', 'recovered plaintext',
            '<div class="output-box">' . lk_visible($plain, 4000) . '</div>'
            . '<p class="text-muted">' . $queries . ' oracle queries. Each one answered a single yes/no question
               about padding; nothing else was ever returned.</p>');
        break;
    }

    /* ------------------------------------------------------------ length extension */
    case 'lenext': {
        $data   = (string)($_POST['data'] ?? '');
        $mac    = strtolower(trim((string)($_POST['mac'] ?? '')));
        $suffix = (string)($_POST['suffix'] ?? '');
        $rows   = '';
        for ($sl = 1; $sl <= 32; $sl++) {
            $glue    = cl_sha1_padding($sl + strlen($data));
            $newData = $data . $glue . $suffix;
            $newMac  = cl_sha1($suffix, cl_sha1_state_from_digest($mac), $sl + strlen($data) + strlen($glue));
            $rows .= '<tr><td>secret len ' . $sl . '</td><td><code>' . $newMac . '</code><br>'
                  . '<textarea class="form-control cl-mono" rows="2" onclick="this.select()">'
                  . lk_esc(rawurlencode($newData)) . '</textarea></td></tr>';
        }
        $out = wb_box('LENGTH EXTENSION', 'one candidate per secret length',
            '<p class="text-muted">Send each row until one is accepted. The <code>data</code> value is
             URL-encoded because the glue padding contains raw bytes.</p>'
            . '<table class="lk-kv">' . $rows . '</table>');
        break;
    }

    /* ------------------------------------------------------------ timing */
    case 'timing': {
        $alpha   = str_split('0123456789abcdef');
        $len     = max(1, (int)($_POST['len'] ?? 16));
        $samples = max(1, min(9, (int)($_POST['samples'] ?? 3)));
        $prefix  = '';
        $tables  = '';

        for ($pos = 0; $pos < $len; $pos++) {
            $best = null;
            $bestMs = -1;
            $row = '';
            foreach ($alpha as $c) {
                $guess = str_pad($prefix . $c, $len, '0');
                $times = [];
                for ($s = 0; $s < $samples; $s++) {
                    $t0 = microtime(true);
                    wb_oracle('level=8&token=' . rawurlencode($guess));
                    $times[] = (microtime(true) - $t0) * 1000;
                }
                sort($times);
                $median = $times[intdiv(count($times), 2)];
                $row .= '<tr><td>' . $c . '</td><td>' . number_format($median, 1) . ' ms</td></tr>';
                if ($median > $bestMs) {
                    $bestMs = $median;
                    $best   = $c;
                }
            }
            $prefix .= $best;
            $tables .= '<details><summary>position ' . $pos . ' &rarr; <code>' . $best . '</code> ('
                    . number_format($bestMs, 1) . ' ms)</summary><table class="lk-kv">' . $row . '</table></details>';
        }
        $out = wb_box('TIMING HARNESS', 'median of ' . $samples . ' samples per candidate',
            '<div class="output-box">' . lk_esc($prefix) . '</div>' . $tables
            . '<p class="text-muted">Each position adds about 12 ms when correct. If two candidates are within
               noise, raise the sample count rather than guessing.</p>');
        break;
    }

    /* ------------------------------------------------------------ seed cracker */
    case 'seed': {
        $prefix = strtolower(trim((string)($_POST['prefix'] ?? '')));
        $from   = (int)($_POST['from'] ?? 0);
        $to     = (int)($_POST['to'] ?? 0);
        $hits   = '';
        $n      = 0;
        for ($t = $from; $t <= $to && $n < 5000; $t++, $n++) {
            $tok = cl_l9_token_from_seed($t);
            if ($prefix !== '' && str_starts_with($tok, $prefix)) {
                $hits .= '<tr><td>seed ' . $t . '</td><td><code>' . $tok . '</code></td></tr>';
            }
        }
        $out = wb_box('SEED CRACKER', 'mt_srand(t) over ' . $n . ' candidate seconds',
            $hits !== ''
                ? '<table class="lk-kv">' . $hits . '</table>'
                : '<div class="message error">No token in that window starts with that prefix. Check the window
                     bounds and the prefix.</div>');
        break;
    }
}

require_once __DIR__ . '/secrets.php';
$lab = cryptolab();
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Crypto Workbench — <?= lk_esc($lab['name']) ?></title>
<link rel="stylesheet" href="css/styles.css">
<?= crypto_extra_head() ?>
<style>.wb-grid{display:grid;grid-template-columns:1fr;gap:1rem}@media(min-width:1050px){.wb-grid{grid-template-columns:1fr 1fr}}
details{margin:0.4rem 0}summary{cursor:pointer;font-size:0.8rem;color:var(--text-muted)}</style>
</head>
<body>
<header class="header">
    <div class="header-left"><h1>Crypto Workbench</h1><p>Encoding · XOR · blocks · oracle runners</p></div>
    <div class="header-right"><a href="index.php" class="back-btn">&larr; Levels</a></div>
</header>

<div class="container">
    <div class="scenario">
        These tools do the arithmetic and the loops, and print their intermediate values while they do it.
        Read the intermediate values &mdash; they are where the lesson is. The runners talk to
        <code>oracle.php</code> over HTTP exactly as an external script would.
    </div>

    <?= $out ?>

    <div class="wb-grid">
        <div class="code-panel"><div class="panel-header"><span class="panel-label">Byte pushing</span></div>
        <div class="panel-body">

            <form method="post" class="lk-box"><div class="lk-body">
                <label class="form-label">hex / base64url</label>
                <textarea name="value" rows="3" class="form-control cl-mono"><?= lk_esc($_POST['value'] ?? '') ?></textarea>
                <select name="mode" class="form-control" style="margin-top:0.4rem">
                    <option value="hex-enc">text &rarr; hex</option>
                    <option value="hex-dec">hex &rarr; text</option>
                    <option value="b64-enc">text &rarr; base64url</option>
                    <option value="b64-dec">base64url &rarr; text</option>
                </select>
                <button class="btn btn-outline" style="margin-top:0.4rem" name="action" value="encode">Run</button>
            </div></form>

            <form method="post" class="lk-box"><div class="lk-body">
                <label class="form-label">XOR two values</label>
                <input name="a" class="form-control cl-mono" placeholder="a (hex)" value="<?= lk_esc($_POST['a'] ?? '') ?>">
                <input name="b" class="form-control cl-mono" style="margin-top:0.4rem" placeholder="b" value="<?= lk_esc($_POST['b'] ?? '') ?>">
                <label style="font-size:0.78rem;color:var(--text-muted);display:block;margin-top:0.3rem">
                    <input type="checkbox" name="b_is_text" value="1"> b is plain text, not hex
                </label>
                <button class="btn btn-outline" style="margin-top:0.4rem" name="action" value="xor">XOR</button>
            </div></form>

            <form method="post" class="lk-box"><div class="lk-body">
                <label class="form-label">Split into blocks / detect ECB</label>
                <textarea name="ct" rows="3" class="form-control cl-mono" placeholder="ciphertext (hex)"></textarea>
                <button class="btn btn-outline" style="margin-top:0.4rem" name="action" value="blocks">Split</button>
            </div></form>

            <form method="post" class="lk-box"><div class="lk-body">
                <label class="form-label">CBC bit-flip calculator</label>
                <textarea name="token" rows="3" class="form-control cl-mono" placeholder="token (hex)"></textarea>
                <input name="block" class="form-control cl-mono" style="margin-top:0.4rem" placeholder="target plaintext block index (1)" value="1">
                <input name="current" class="form-control cl-mono" style="margin-top:0.4rem" placeholder="current text of that block">
                <input name="target" class="form-control cl-mono" style="margin-top:0.4rem" placeholder="text you want instead">
                <label style="font-size:0.78rem;color:var(--text-muted);display:block;margin-top:0.3rem">
                    <input type="checkbox" name="has_iv" value="1" checked> token starts with a 16-byte IV
                </label>
                <button class="btn btn-outline" style="margin-top:0.4rem" name="action" value="cbcflip">Compute</button>
            </div></form>

        </div></div>

        <div class="challenge-panel"><div class="panel-header"><span class="panel-label">Oracle runners</span></div>
        <div class="panel-body">

            <form method="post" class="lk-box"><div class="lk-body">
                <label class="form-label">Level 4 &mdash; ECB byte at a time</label>
                <p class="text-muted">Recovers the appended secret from <code>oracle.php?level=4</code>, printing the
                alignment used for each byte.</p>
                <button class="btn btn-outline" name="action" value="ecb">Run</button>
            </div></form>

            <form method="post" class="lk-box"><div class="lk-body">
                <label class="form-label">Level 6 &mdash; padding oracle</label>
                <textarea name="ct" rows="3" class="form-control cl-mono" placeholder="IV || ciphertext (hex)"></textarea>
                <button class="btn btn-outline" style="margin-top:0.4rem" name="action" value="padding">Decrypt</button>
            </div></form>

            <form method="post" class="lk-box"><div class="lk-body">
                <label class="form-label">Level 7 &mdash; SHA-1 length extension</label>
                <input name="data" class="form-control cl-mono" placeholder="original data" value="<?= lk_esc($_POST['data'] ?? '') ?>">
                <input name="mac" class="form-control cl-mono" style="margin-top:0.4rem" placeholder="original mac (sha1 hex)" value="<?= lk_esc($_POST['mac'] ?? '') ?>">
                <input name="suffix" class="form-control cl-mono" style="margin-top:0.4rem" placeholder="&amp;role=admin" value="<?= lk_esc($_POST['suffix'] ?? '') ?>">
                <button class="btn btn-outline" style="margin-top:0.4rem" name="action" value="lenext">Forge</button>
            </div></form>

            <form method="post" class="lk-box"><div class="lk-body">
                <label class="form-label">Level 8 &mdash; timing harness</label>
                <input name="len" class="form-control cl-mono" placeholder="token length" value="16">
                <input name="samples" class="form-control cl-mono" style="margin-top:0.4rem" placeholder="samples per candidate" value="3">
                <p class="text-muted">16 positions x 16 candidates x samples, at roughly 12 ms of server delay per
                correct byte. Expect this to take a minute.</p>
                <button class="btn btn-outline" name="action" value="timing">Run</button>
            </div></form>

            <form method="post" class="lk-box"><div class="lk-body">
                <label class="form-label">Level 9 &mdash; mt_rand seed cracker</label>
                <input name="prefix" class="form-control cl-mono" placeholder="known token prefix" value="<?= lk_esc($_POST['prefix'] ?? '') ?>">
                <input name="from" class="form-control cl-mono" style="margin-top:0.4rem" placeholder="window start (unix)" value="<?= lk_esc($_POST['from'] ?? '1756900000') ?>">
                <input name="to" class="form-control cl-mono" style="margin-top:0.4rem" placeholder="window end (unix)" value="<?= lk_esc($_POST['to'] ?? '1756900180') ?>">
                <button class="btn btn-outline" style="margin-top:0.4rem" name="action" value="seed">Search</button>
            </div></form>

        </div></div>
    </div>
</div>
</body>
</html>
