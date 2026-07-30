<?php
/**
 * collector.php — internal out-of-band callback sink for Level 3.
 *
 * The malicious external DTD (oob.dtd) makes the XML parser request
 *   http://127.0.0.1/collector.php?data=<base64 of the secret file>
 * This endpoint records the captured value; level3.php then confirms it
 * server-side. Reads the raw query string so base64 padding/"+"/"/"
 * survive without url-decoding surprises.
 */
require_once __DIR__ . '/helpers.php';

$qs   = $_SERVER['QUERY_STRING'] ?? '';
$data = '';
if (preg_match('/(?:^|&)data=([^&]*)/', $qs, $m)) {
    $data = $m[1];
}

if ($data !== '') {
    xxe_collector_record($data);
}

// Blind endpoint: return nothing useful.
header('Content-Type: text/plain');
echo '';
