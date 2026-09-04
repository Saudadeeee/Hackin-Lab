<?php
/**
 * The issuer's public key material.
 *
 * Publishing this is CORRECT for RS256 - a public key is public by definition.
 * Level 5 exists to show that "public" only stays harmless while the server
 * refuses to treat it as a symmetric secret.
 */
require_once __DIR__ . '/jwt.php';

$pem = jwt_public_key();

if (isset($_GET['pem'])) {
    header('Content-Type: text/plain; charset=utf-8');
    echo $pem;                 // exact bytes, including the trailing newline
    exit;
}

$res = openssl_pkey_get_public($pem);
$det = $res ? openssl_pkey_get_details($res) : null;

header('Content-Type: application/json');
echo json_encode([
    'keys' => $det ? [[
        'kty' => 'RSA',
        'kid' => 'main-2024',
        'use' => 'sig',
        'alg' => 'RS256',
        'n'   => jwt_b64url_encode($det['rsa']['n']),
        'e'   => jwt_b64url_encode($det['rsa']['e']),
    ]] : [],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
