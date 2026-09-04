<?php
/**
 * The lab's oracle endpoints.
 *
 * Real attacks are scripted against an endpoint, not clicked through a form,
 * so the levels that need many queries expose one here. Each returns plain
 * text and is safe to hammer from a loop.
 *
 *   GET  oracle.php?level=4&prefix=<hex>   -> hex of ECB(prefix || SECRET)
 *   GET  oracle.php?level=6&ct=<hex>       -> "padding-ok" | "padding-bad"
 *   GET  oracle.php?level=8&token=<ascii>  -> "ok" | "no"   (timing is the signal)
 *   GET  oracle.php?level=9&issue=1        -> "<unix time>:<token>"
 */
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/secrets.php';

header('Content-Type: text/plain; charset=utf-8');

$level = (int)($_GET['level'] ?? 0);

switch ($level) {

    case 4:
        // Encryption oracle: ECB( attacker_prefix || SECRET )
        $prefix = cl_unhex((string)($_GET['prefix'] ?? ''));
        echo cl_hex(cl_aes_ecb_encrypt($prefix . cl_secret_l4(), cl_key(4)));
        break;

    case 6:
        // Padding oracle: the response distinguishes a padding failure from a
        // successful decrypt. That single bit is the whole vulnerability.
        $blob = cl_unhex((string)($_GET['ct'] ?? ''));
        if (strlen($blob) < 32 || strlen($blob) % 16 !== 0) {
            echo 'malformed';
            break;
        }
        $iv     = substr($blob, 0, 16);
        $cipher = substr($blob, 16);
        $plain  = cl_pkcs7_unpad(cl_aes_cbc_decrypt_raw($cipher, cl_key(6), $iv));
        echo $plain === null ? 'padding-bad' : 'padding-ok';
        break;

    case 8:
        // Timing side channel: the comparison returns as soon as bytes differ,
        // and each matching byte costs a measurable amount of time.
        $given  = (string)($_GET['token'] ?? '');
        $secret = cl_secret_l8();
        $ok     = true;
        $n      = max(strlen($given), strlen($secret));
        for ($i = 0; $i < $n; $i++) {
            if (($given[$i] ?? '') !== ($secret[$i] ?? '')) {
                $ok = false;
                break;
            }
            usleep(12000);          // stands in for a slow per-byte lookup
        }
        echo $ok ? 'ok' : 'no';
        break;

    case 9:
        // Issue a token the same way the app does, and disclose the second it
        // was generated - which is also the seed.
        $t = time();
        mt_srand($t);
        echo $t . ':' . cl_l9_token_from_seed($t);
        break;

    default:
        http_response_code(400);
        echo "usage:\n"
           . "  oracle.php?level=4&prefix=<hex>\n"
           . "  oracle.php?level=6&ct=<hex>\n"
           . "  oracle.php?level=8&token=<ascii>\n"
           . "  oracle.php?level=9&issue=1\n";
}
