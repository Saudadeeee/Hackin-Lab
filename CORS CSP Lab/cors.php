<?php
/**
 * CORS CSP Lab · the five CORS policies, in one place.
 *
 * These functions are the *real* policies. api.php calls them, the level pages
 * display them, and nothing anywhere re-implements them. Whatever you see in a
 * level's source panel is the code that produced the headers in the trace.
 */

/** The only origin the fictional company actually meant to trust. */
function cors_trusted_origin(): string
{
    return 'https://portal.hackinlab.internal';
}

/** Session cookie the lab's browser is holding when it calls the API. */
function cors_session_cookie(): string
{
    return 'hl_session=demo.5f31c2a9';
}

/**
 * The account data api.php returns. It is only returned when the request
 * carried the session cookie - that is what "with credentials" means.
 */
function cors_account_json(bool $authenticated): string
{
    if (!$authenticated) {
        return json_encode(
            ['error' => 'not authenticated', 'hint' => 'this endpoint needs the session cookie'],
            JSON_PRETTY_PRINT
        );
    }
    return json_encode([
        'user'    => 'a.mendes',
        'account' => 'HL-4471-0092',
        'balance' => 128430.55,
        'api_key' => 'hlk_live_9f2b7c41d0e6',
    ], JSON_PRETTY_PRINT);
}

/**
 * Decide the CORS response headers for one level.
 *
 * Returns the header lines exactly as api.php will emit them. An empty array
 * means "no CORS headers at all", which a browser treats as a refusal.
 *
 * @return string[]
 */
function cors_policy_headers(int $level, string $origin): array
{
    $out = [];

    switch ($level) {

        /* ---- Level 1: echo whatever arrived. -------------------------- */
        case 1:
            if ($origin !== '') {
                $out[] = 'Access-Control-Allow-Origin: ' . $origin;
                $out[] = 'Access-Control-Allow-Credentials: true';
                $out[] = 'Vary: Origin';
            }
            break;

        /* ---- Level 2: an allowlist that contains the string "null". ---- */
        case 2:
            $allowlist = [
                'https://portal.hackinlab.internal',
                'https://admin.hackinlab.internal',
                'null',   // "the mobile webview and the sandboxed preview send this"
            ];
            if (in_array($origin, $allowlist, true)) {
                $out[] = 'Access-Control-Allow-Origin: ' . $origin;
                $out[] = 'Access-Control-Allow-Credentials: true';
                $out[] = 'Vary: Origin';
            }
            break;

        /* ---- Level 3: regex anchored only at the start. ---------------- */
        case 3:
            if ($origin !== '' && preg_match('~^https?://portal\.hackinlab\.internal~', $origin)) {
                $out[] = 'Access-Control-Allow-Origin: ' . $origin;
                $out[] = 'Access-Control-Allow-Credentials: true';
                $out[] = 'Vary: Origin';
            }
            break;

        /* ---- Level 4: suffix test on the whole origin string. ---------- */
        case 4:
            if ($origin !== '' && str_ends_with($origin, 'hackinlab.internal')) {
                $out[] = 'Access-Control-Allow-Origin: ' . $origin;
                $out[] = 'Access-Control-Allow-Credentials: true';
                $out[] = 'Vary: Origin';
            }
            break;

        /* ---- Level 5: a correct *.hackinlab.internal wildcard. --------- */
        case 5:
            $parts  = parse_url($origin);
            $scheme = is_array($parts) ? ($parts['scheme'] ?? '') : '';
            $host   = is_array($parts) ? ($parts['host']   ?? '') : '';
            $ok = in_array($scheme, ['http', 'https'], true)
                && ($host === 'hackinlab.internal' || str_ends_with($host, '.hackinlab.internal'));
            if ($ok) {
                $out[] = 'Access-Control-Allow-Origin: ' . $origin;
                $out[] = 'Access-Control-Allow-Credentials: true';
                $out[] = 'Vary: Origin';
            }
            break;
    }

    return $out;
}

/* =========================================================================
 * Effect analysis - used by the level pages to decide the flag.
 * Everything here reads the RESPONSE, never the payload.
 * ===================================================================== */

/**
 * Parse a raw response header block into a lowercase-keyed map. Repeated
 * headers keep the last value, which is what a browser does for
 * Access-Control-Allow-Origin.
 */
function cors_header_map(array $rawHeaders): array
{
    $map = [];
    foreach ($rawHeaders as $line) {
        $pos = strpos($line, ':');
        if ($pos === false) {
            continue;   // the "HTTP/1.1 200 OK" status line
        }
        $map[strtolower(trim(substr($line, 0, $pos)))] = trim(substr($line, $pos + 1));
    }
    return $map;
}

/**
 * What a browser would do with this response, for a request from $origin.
 * The verdict is derived only from the headers the server actually sent.
 *
 * @return array{acao:string, acac:string, readable:bool, credentialed:bool, note:string}
 */
function cors_browser_verdict(string $origin, array $headerMap): array
{
    $acao  = $headerMap['access-control-allow-origin'] ?? '';
    $acac  = $headerMap['access-control-allow-credentials'] ?? '';
    $creds = strtolower($acac) === 'true';

    if ($acao === '') {
        return ['acao' => '', 'acac' => $acac, 'readable' => false, 'credentialed' => false,
                'note' => 'No Access-Control-Allow-Origin header. The browser fetched the response but will not let script read it.'];
    }
    if ($acao === '*' && $creds) {
        return ['acao' => $acao, 'acac' => $acac, 'readable' => false, 'credentialed' => false,
                'note' => 'The wildcard cannot be combined with credentials. A browser rejects that pair outright.'];
    }
    if ($acao === '*') {
        return ['acao' => $acao, 'acac' => $acac, 'readable' => true, 'credentialed' => false,
                'note' => 'Readable, but a wildcard response is only reachable by a request sent without cookies, so only public data comes back.'];
    }
    if ($acao !== $origin) {
        return ['acao' => $acao, 'acac' => $acac, 'readable' => false, 'credentialed' => false,
                'note' => 'Access-Control-Allow-Origin names a different origin than the one that asked. The browser blocks the read.'];
    }
    return ['acao' => $acao, 'acac' => $acac, 'readable' => true, 'credentialed' => $creds,
            'note' => $creds
                ? 'The origin is echoed back and credentials are allowed: script on that origin reads this response with the victim&rsquo;s cookies attached.'
                : 'Readable cross-origin, but without credentials, so this is the logged-out response.'];
}

/** Host of an origin string, or '' when it does not parse as an origin. */
function cors_origin_host(string $origin): string
{
    $p = parse_url($origin);
    if (!is_array($p) || empty($p['host']) || empty($p['scheme'])) {
        return '';
    }
    return strtolower($p['host']);
}

/** True when $host is hackinlab.internal or a genuine subdomain of it. */
function cors_is_internal_host(string $host): bool
{
    return $host === 'hackinlab.internal' || str_ends_with($host, '.hackinlab.internal');
}
