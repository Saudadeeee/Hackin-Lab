<?php
/**
 * Values the levels are trying to protect.
 *
 * They live here rather than in the level pages so that the source panels can
 * show the real code without also showing the answer.
 */
require_once __DIR__ . '/crypto.php';

/** Level 4: appended to attacker input before ECB encryption. */
function cl_secret_l4(): string
{
    return 'secret=blocks_are_independent;lvl=4';
}

/** Level 6: the plaintext an attacker recovers through the padding oracle. */
function cl_secret_l6(): string
{
    return 'transfer=50000;to=acct-9931;memo=padding_tells_all';
}

/** Level 7: the HMAC-style secret prefix. 14 bytes, length unknown to the attacker. */
function cl_secret_l7(): string
{
    return 'ItsNotAMacKey1';
}

/** Level 8: the admin API token compared one byte at a time. */
function cl_secret_l8(): string
{
    return 'a7f3c9d2e1b40856';
}

/** Level 9: how the application derives a session token from its PRNG state. */
function cl_l9_token_from_seed(int $seed): string
{
    mt_srand($seed);
    $t = '';
    for ($i = 0; $i < 4; $i++) {
        $t .= str_pad(dechex(mt_rand(0, 0xFFFF)), 4, '0', STR_PAD_LEFT);
    }
    return $t;
}

/** Level 9: the second at which the administrator's token was minted. */
function cl_l9_admin_seed(): int
{
    // Somewhere inside the window the level discloses. Stable across restarts.
    return 1756900000 + (int)(hexdec(substr(hash('sha256', CRYPTO_LAB_SEED . '|l9'), 0, 4)) % 180);
}

/** Level 10: the administrator's session string, encrypted under the reused nonce. */
function cl_secret_l10(): string
{
    return 'user=admin;role=admin;id=1;mfa=passed';
}
