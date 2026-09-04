<?php
/**
 * CORS CSP Lab · the JSONP endpoint level 6 uses.
 *
 * JSONP predates CORS. It works by returning JavaScript instead of JSON: the
 * caller supplies a function name, the server wraps the data in a call to it,
 * and a <script> tag executes the result. That means the callback name is
 * attacker-supplied text placed in executable position, which is exactly the
 * property a CSP allowlist cannot see.
 *
 * The application's own page calls this with callback=renderProducts.
 */

$callback = (string)($_GET['callback'] ?? 'renderProducts');

// The only validation: keep the header line intact. Nothing here restricts the
// callback to an identifier, which is the whole bug.
$callback = str_replace(["\r", "\n", "\0"], '', $callback);

$data = [
    ['sku' => 'HL-1001', 'name' => 'Status board licence', 'price' => 49.00],
    ['sku' => 'HL-1002', 'name' => 'Portal seat',          'price' => 12.50],
];

header('Content-Type: application/javascript');
header('Cache-Control: no-store');
echo $callback . '(' . json_encode(['products' => $data]) . ');';
