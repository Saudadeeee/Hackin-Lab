<?php
/**
 * CORS CSP Lab · the account API the CORS levels attack.
 *
 * One endpoint, five policies, selected with ?level=N. The headers it emits
 * come from cors_policy_headers() in cors.php - the same function the level
 * pages print in their source panel.
 */

require_once __DIR__ . '/cors.php';

$level  = (int)($_GET['level'] ?? 1);
$origin = (string)($_SERVER['HTTP_ORIGIN'] ?? '');

// PHP rejects request headers containing CR or LF, but be explicit about it:
// a header value is a single line and nothing here may change that.
$origin = str_replace(["\r", "\n", "\0"], '', $origin);

foreach (cors_policy_headers($level, $origin) as $line) {
    header($line, false);
}

// A preflight gets the same access decision plus the method and header lists.
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, X-Requested-With');
    header('Access-Control-Max-Age: 600');
    http_response_code(204);
    exit;
}

// "With credentials" is only interesting because there is something behind the
// session cookie. Without it the endpoint returns the logged-out response.
$cookie        = (string)($_SERVER['HTTP_COOKIE'] ?? '');
$authenticated = strpos($cookie, 'hl_session=') !== false;

header('Content-Type: application/json');
header('Cache-Control: no-store');
echo cors_account_json($authenticated);
