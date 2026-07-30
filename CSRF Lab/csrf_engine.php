<?php
/**
 * CSRF Lab — Core Engine
 *
 * Models a logged-in "victim admin" and a server-side bot (visit.php) that
 * performs the learner's crafted PoC request AS the admin — exactly like a
 * real victim opening an attacker's page while authenticated.
 *
 * The bot:
 *   1. parses the PoC (a URL, <img>/<a>, an HTML <form>, or a fetch() call),
 *   2. reconstructs the request the victim's browser would send (method,
 *      params, body, content-type, whether the SameSite session cookie is
 *      attached, whether a Referer is sent, attacker-set cookies),
 *   3. runs the level's REAL state-changing handler with the admin session.
 *
 * If the state-changing action succeeds WITHOUT a valid anti-CSRF token under
 * that level's protection, the admin state actually changes and the level is
 * marked solved — the flag is awarded for the genuine bypass, never by string
 * matching the flag.
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ── Fixed victim/attacker identities ──────────────────────────
const CSRF_ADMIN_EMAIL_DEFAULT = 'admin@corp.local';
const CSRF_ATTACKER_EMAIL      = 'attacker@evil.com';   // used in worked examples
const CSRF_TARGET_USER         = 'mallory';             // account the attacker promotes
const CSRF_APP_HOST            = 'csrf-lab.local';      // the victim application's own origin
const CSRF_ATTACKER_ORIGIN     = 'https://evil.attacker.example';
const CSRF_STATIC_TOKEN        = 'a1b2c3d4';            // level 4: hardcoded, predictable token

/* ============================================================
   Per-level victim/admin state (isolated per learner session)
   ============================================================ */

function csrf_default_state(): array {
    return [
        'admin_email'   => CSRF_ADMIN_EMAIL_DEFAULT,
        'target_role'   => 'user',   // role of the "mallory" account
        'promoted_user' => '',
        'owner'         => 'admin',  // account owner (level 10)
        'session_token' => bin2hex(random_bytes(16)), // the REAL session-bound token (hidden)
        'solved'        => false,
    ];
}

function csrf_init_level(int $level): void {
    if (!isset($_SESSION['csrf']) || !is_array($_SESSION['csrf'])) {
        $_SESSION['csrf'] = [];
    }
    if (!isset($_SESSION['csrf'][$level]) || !is_array($_SESSION['csrf'][$level])) {
        $_SESSION['csrf'][$level] = csrf_default_state();
    }
}

function csrf_get_state(int $level): array {
    csrf_init_level($level);
    return $_SESSION['csrf'][$level];
}

function csrf_reset_level(int $level): void {
    csrf_init_level($level);
    $solved = $_SESSION['csrf'][$level]['solved'] ?? false;
    $token  = $_SESSION['csrf'][$level]['session_token'] ?? bin2hex(random_bytes(16));
    $fresh  = csrf_default_state();
    $fresh['solved']        = $solved;   // keep captured flags visible after a reset
    $fresh['session_token'] = $token;
    $_SESSION['csrf'][$level] = $fresh;
    if (isset($_SESSION['csrf_result'][$level])) {
        unset($_SESSION['csrf_result'][$level]);
    }
}

/* ============================================================
   PoC parser — turns attacker HTML/JS into a victim request
   ============================================================ */

/** Extract an HTML attribute value, tolerating single/double/unquoted forms. */
function csrf_attr(string $attrs, string $name): ?string {
    $n = preg_quote($name, '/');
    if (preg_match('/\b' . $n . '\s*=\s*"([^"]*)"/i', $attrs, $m)) return $m[1];
    if (preg_match('/\b' . $n . "\\s*=\\s*'([^']*)'/i", $attrs, $m)) return $m[1];
    if (preg_match('/\b' . $n . '\s*=\s*([^\s>]+)/i', $attrs, $m))   return $m[1];
    return null;
}

/** Does the PoC declare a no-referrer policy (suppressing the Referer header)? */
function csrf_has_no_referrer(string $poc): bool {
    return (bool)preg_match('/no-?referrer/i', $poc);
}

/** Cookies the attacker page sets via document.cookie (e.g. double-submit token). */
function csrf_extract_cookies(string $poc): array {
    $cookies = [];
    if (preg_match_all('/document\.cookie\s*=\s*["\']([^"\';]+)/i', $poc, $m)) {
        foreach ($m[1] as $pair) {
            if (strpos($pair, '=') !== false) {
                [$k, $v] = explode('=', $pair, 2);
                $cookies[trim($k)] = trim($v);
            }
        }
    }
    return $cookies;
}

/** Split a URL/path into [endpoint basename, query params]. */
function csrf_url_parts(string $url): array {
    $url = trim($url);
    $url = preg_replace('#^[a-z][a-z0-9+.\-]*://[^/]+#i', '', $url); // strip scheme+host
    $path = $url;
    $query = '';
    if (strpos($url, '?') !== false) {
        [$path, $query] = explode('?', $url, 2);
    }
    $path = ltrim($path, '/');
    $target = (strpos($path, '/') !== false) ? substr($path, strrpos($path, '/') + 1) : $path;
    $params = [];
    if ($query !== '') {
        parse_str($query, $params);
    }
    return [$target, $params];
}

function csrf_find_fetch(string $poc): ?array {
    if (!preg_match('/fetch\s*\(\s*["\']([^"\']+)["\']/i', $poc, $m)) return null;
    $method = 'GET'; $ct = ''; $body = '';
    if (preg_match('/method\s*:\s*["\'](\w+)["\']/i', $poc, $mm))              $method = strtoupper($mm[1]);
    if (preg_match('/content-type["\']?\s*:\s*["\']([^"\']+)["\']/i', $poc, $mc)) $ct = $mc[1];
    if (preg_match('/body\s*:\s*(["\'`])((?:\\\\.|(?!\1).)*)\1/is', $poc, $mb)) $body = $mb[2];
    return ['url' => $m[1], 'method' => $method, 'content_type' => $ct, 'body' => $body, 'kind' => 'json_request'];
}

function csrf_find_form(string $poc): ?array {
    if (!preg_match('/<form\b([^>]*)>(.*?)<\/form>/is', $poc, $m)) return null;
    $action  = csrf_attr($m[1], 'action') ?? '';
    $method  = strtoupper(csrf_attr($m[1], 'method') ?? 'GET');
    $enctype = strtolower(csrf_attr($m[1], 'enctype') ?? '');
    $fields  = [];
    if (preg_match_all('/<(?:input|textarea|button)\b([^>]*)>/is', $m[2], $im)) {
        foreach ($im[1] as $ia) {
            $name = csrf_attr($ia, 'name');
            if ($name === null) continue;
            $fields[$name] = csrf_attr($ia, 'value') ?? '';
        }
    }
    return ['url' => $action, 'method' => $method, 'enctype' => $enctype, 'fields' => $fields];
}

function csrf_find_meta_refresh(string $poc): ?array {
    if (!preg_match('/<meta\b[^>]*http-equiv\s*=\s*["\']?refresh[^>]*>/i', $poc, $m)) return null;
    $content = csrf_attr($m[0], 'content') ?? '';
    if (preg_match('/url\s*=\s*([^\s;"\']+)/i', $content, $mm)) {
        return ['url' => $mm[1], 'method' => 'GET', 'kind' => 'top_nav_get'];
    }
    return null;
}

function csrf_find_location(string $poc): ?array {
    if (preg_match('/(?:window\.)?location(?:\.href|\.assign|\.replace)?\s*(?:=|\()\s*["\']([^"\']+)["\']/i', $poc, $m)) {
        return ['url' => $m[1], 'method' => 'GET', 'kind' => 'top_nav_get'];
    }
    return null;
}

function csrf_find_anchor(string $poc): ?array {
    if (preg_match('/<a\b([^>]*)>/is', $poc, $m)) {
        $href = csrf_attr($m[1], 'href');
        if ($href !== null && $href !== '') {
            return ['url' => $href, 'method' => 'GET', 'kind' => 'top_nav_get'];
        }
    }
    return null;
}

function csrf_find_img(string $poc): ?array {
    if (preg_match('/<img\b([^>]*)>/is', $poc, $m)) {
        $src = csrf_attr($m[1], 'src');
        if ($src !== null && $src !== '') {
            return ['url' => $src, 'method' => 'GET', 'kind' => 'subresource_get'];
        }
    }
    return null;
}

function csrf_find_bare_url(string $poc): ?array {
    $t = trim($poc);
    if ($t === '' || strpos($t, '<') !== false) return null;
    if (preg_match('#^(?:https?://\S+|/?[\w.\-]+\.php(?:\?\S*)?)$#i', $t)) {
        return ['url' => $t, 'method' => 'GET', 'kind' => 'top_nav_get'];
    }
    return null;
}

/**
 * Parse a PoC into a normalized victim request.
 * @return array{found: bool, req: array}
 */
function csrf_parse_poc(string $poc): array {
    $poc = (string)$poc;
    $noRef = csrf_has_no_referrer($poc);

    $req = [
        'method'        => 'GET',
        'target'        => '',
        'params'        => [],
        'raw_body'      => '',
        'content_type'  => '',
        'kind'          => 'unknown',
        'referer_sent'  => !$noRef,
        'origin_sent'   => !$noRef,
        'extra_cookies' => csrf_extract_cookies($poc),
    ];

    $hit = csrf_find_fetch($poc)
        ?? csrf_find_form($poc)
        ?? csrf_find_meta_refresh($poc)
        ?? csrf_find_location($poc)
        ?? csrf_find_anchor($poc)
        ?? csrf_find_img($poc)
        ?? csrf_find_bare_url($poc);

    if ($hit === null) {
        return ['found' => false, 'req' => $req];
    }

    [$target, $qparams] = csrf_url_parts($hit['url']);
    $req['target'] = $target;
    $req['method'] = $hit['method'] ?? 'GET';
    $req['kind']   = $hit['kind'] ?? ($req['method'] === 'POST' ? 'form_post' : 'top_nav_get');
    $params        = $qparams;

    if (isset($hit['fields'])) {
        $enctype = $hit['enctype'] ?? '';
        if ($req['method'] === 'POST') {
            $req['kind'] = 'form_post';
            if (strpos($enctype, 'text/plain') !== false) {
                $req['content_type'] = 'text/plain';
                $lines = [];
                foreach ($hit['fields'] as $n => $v) { $lines[] = $n . '=' . $v; }
                $req['raw_body'] = implode("\r\n", $lines);
            } elseif (strpos($enctype, 'multipart') !== false) {
                $req['content_type'] = 'multipart/form-data';
                $req['raw_body']     = http_build_query($hit['fields']);
            } else {
                $req['content_type'] = 'application/x-www-form-urlencoded';
                $req['raw_body']     = http_build_query($hit['fields']);
            }
        } else {
            $req['kind'] = 'top_nav_get'; // a GET form navigates top-level
        }
        $params = array_merge($params, $hit['fields']);
    }

    if (!empty($hit['content_type'])) $req['content_type'] = $hit['content_type'];
    if (!empty($hit['body'])) {
        $req['raw_body'] = $hit['body'];
        $decoded = json_decode($hit['body'], true);
        if (is_array($decoded)) {
            $params = array_merge($params, $decoded);
        } else {
            parse_str($hit['body'], $pp);
            if (is_array($pp)) $params = array_merge($params, $pp);
        }
    }

    // text/plain form trick: the body is smuggled JSON — surface it in params too.
    if ($req['raw_body'] !== '' && !isset($params['email'])) {
        $decoded = json_decode($req['raw_body'], true);
        if (is_array($decoded)) $params = array_merge($params, $decoded);
    }

    $req['params'] = $params;
    return ['found' => true, 'req' => $req];
}

/* ============================================================
   Victim browser model + per-level state-changing handlers
   ============================================================ */

function csrf_res(bool $ok, string $reason): array {
    return ['ok' => $ok, 'reason' => $reason];
}

function csrf_expected_endpoint(int $level): string {
    $map = [
        1 => 'change_email.php', 2 => 'change_email.php', 3 => 'change_email.php',
        4 => 'promote.php',      5 => 'change_email.php', 6 => 'quick_email.php',
        7 => 'api_update.php',   8 => 'change_email.php', 9 => 'promote.php',
        10 => 'transfer_owner.php',
    ];
    return $map[$level] ?? '';
}

/** SameSite policy on the admin_session cookie for this level. */
function csrf_samesite(int $level): string {
    return in_array($level, [6, 10], true) ? 'Lax' : 'None';
}

/**
 * Would the victim's browser attach the admin_session cookie to this request?
 * SameSite=None → always (cross-site). SameSite=Lax → only top-level GET nav.
 */
function csrf_cookie_sent(int $level, array $req): bool {
    if (csrf_samesite($level) === 'None') return true;
    return ($req['kind'] ?? '') === 'top_nav_get';
}

/** Content types that do NOT trigger a CORS preflight ("simple" requests). */
function csrf_is_simple_content_type(string $ct): bool {
    $ct = strtolower(trim(explode(';', $ct)[0]));
    return in_array($ct, ['', 'text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data'], true);
}

function csrf_handle(int $level, array $req, array &$state): array {
    $expected = csrf_expected_endpoint($level);
    $target   = $req['target'] ?? '';
    if ($target === '') {
        return csrf_res(false, 'The PoC did not target any endpoint.');
    }
    if ($expected !== '' && strcasecmp($target, $expected) !== 0) {
        return csrf_res(false, "PoC targets '{$target}', but this level's vulnerable endpoint is '{$expected}'.");
    }

    $authed = csrf_cookie_sent($level, $req);

    switch ($level) {
        case 1:  return csrf_h_l1($req, $state, $authed);
        case 2:  return csrf_h_l2($req, $state, $authed);
        case 3:  return csrf_h_l3($req, $state, $authed);
        case 4:  return csrf_h_l4($req, $state, $authed);
        case 5:  return csrf_h_l5($req, $state, $authed);
        case 6:  return csrf_h_l6($req, $state, $authed);
        case 7:  return csrf_h_l7($req, $state, $authed);
        case 8:  return csrf_h_l8($req, $state, $authed);
        case 9:  return csrf_h_l9($req, $state, $authed);
        case 10: return csrf_h_l10($req, $state, $authed);
        default: return csrf_res(false, 'Unknown level.');
    }
}

// Level 1 — no token, GET state-change
function csrf_h_l1(array $req, array &$state, bool $authed): array {
    if ($req['method'] !== 'GET') return csrf_res(false, 'change_email.php only accepts GET here.');
    if (!$authed)                 return csrf_res(false, 'The admin session cookie was not sent.');
    $email = trim((string)($req['params']['email'] ?? ''));
    if ($email === '')            return csrf_res(false, 'No email parameter in the request.');
    $state['admin_email'] = $email; // no anti-CSRF token of any kind
    return csrf_res(true, "Admin email changed to {$email} via a forged GET request.");
}

// Level 2 — no token, POST
function csrf_h_l2(array $req, array &$state, bool $authed): array {
    if ($req['method'] !== 'POST') return csrf_res(false, 'change_email.php expects a POST here.');
    if (!$authed)                  return csrf_res(false, 'The admin session cookie was not sent.');
    $email = trim((string)($req['params']['email'] ?? ''));
    if ($email === '')             return csrf_res(false, 'No email field in the POST body.');
    $state['admin_email'] = $email; // no anti-CSRF token on the POST
    return csrf_res(true, "Admin email changed to {$email} via a forged auto-submitting POST form.");
}

// Level 3 — token present in the form but never validated server-side
function csrf_h_l3(array $req, array &$state, bool $authed): array {
    if ($req['method'] !== 'POST') return csrf_res(false, 'change_email.php expects a POST here.');
    if (!$authed)                  return csrf_res(false, 'The admin session cookie was not sent.');
    $token = (string)($req['params']['csrf_token'] ?? '');
    // BUG: the token is read but the comparison against $_SESSION was never written.
    // if ($token !== $_SESSION['csrf_token']) { http_response_code(403); exit; }  <-- MISSING
    $email = trim((string)($req['params']['email'] ?? ''));
    if ($email === '')             return csrf_res(false, 'No email field in the POST body.');
    $state['admin_email'] = $email;
    return csrf_res(true, "Admin email changed to {$email}; the csrf_token field was never checked.");
}

// Level 4 — static / predictable token
function csrf_h_l4(array $req, array &$state, bool $authed): array {
    if ($req['method'] !== 'POST') return csrf_res(false, 'promote.php expects a POST here.');
    if (!$authed)                  return csrf_res(false, 'The admin session cookie was not sent.');
    $token = (string)($req['params']['csrf_token'] ?? '');
    if ($token !== CSRF_STATIC_TOKEN) return csrf_res(false, 'Invalid CSRF token.');
    // BUG: token is a hardcoded constant — identical for every user and session.
    $user = trim((string)($req['params']['user'] ?? ''));
    if ($user === '')              return csrf_res(false, 'No user specified to promote.');
    $state['target_role']   = 'admin';
    $state['promoted_user'] = $user;
    return csrf_res(true, "User '{$user}' promoted to admin using the static, predictable token.");
}

// Level 5 — token validated by FORMAT only, not bound to the session
function csrf_h_l5(array $req, array &$state, bool $authed): array {
    if ($req['method'] !== 'POST') return csrf_res(false, 'change_email.php expects a POST here.');
    if (!$authed)                  return csrf_res(false, 'The admin session cookie was not sent.');
    $token = (string)($req['params']['csrf_token'] ?? '');
    if (!preg_match('/^[a-f0-9]{32}$/i', $token)) return csrf_res(false, 'CSRF token missing or malformed (need 32 hex chars).');
    // BUG: only the format is validated; the token is never compared to $_SESSION['csrf_token'].
    $email = trim((string)($req['params']['email'] ?? ''));
    if ($email === '')             return csrf_res(false, 'No email field in the POST body.');
    $state['admin_email'] = $email;
    return csrf_res(true, "Admin email changed to {$email}; any well-formed token was accepted (not session-bound).");
}

// Level 6 — relies solely on SameSite=Lax; top-level GET navigation still carries the cookie
function csrf_h_l6(array $req, array &$state, bool $authed): array {
    if ($req['method'] !== 'GET') return csrf_res(false, 'quick_email.php only accepts GET.');
    if (!$authed)                 return csrf_res(false, 'SameSite=Lax: the admin_session cookie was NOT sent for this request type (only a top-level GET navigation carries it).');
    // No token at all — the developer assumed SameSite=Lax was sufficient.
    $email = trim((string)($req['params']['email'] ?? ''));
    if ($email === '')            return csrf_res(false, 'No email parameter in the request.');
    $state['admin_email'] = $email;
    return csrf_res(true, "Admin email changed to {$email}; SameSite=Lax still sent the cookie on a top-level GET navigation.");
}

// Level 7 — JSON endpoint reachable with a simple text/plain body (no preflight)
function csrf_h_l7(array $req, array &$state, bool $authed): array {
    if ($req['method'] !== 'POST') return csrf_res(false, 'api_update.php expects a POST here.');
    if (!$authed)                  return csrf_res(false, 'The admin session cookie was not sent.');
    if (!csrf_is_simple_content_type((string)$req['content_type'])) {
        $ct = explode(';', (string)$req['content_type'])[0];
        return csrf_res(false, "Content-Type '{$ct}' triggers a CORS preflight a cross-site page cannot satisfy — the request never reaches the server.");
    }
    $data = json_decode((string)$req['raw_body'], true);
    if (!is_array($data))          return csrf_res(false, 'Request body is not valid JSON the endpoint can parse.');
    $email = trim((string)($data['email'] ?? ''));
    if ($email === '')             return csrf_res(false, 'No "email" key in the JSON body.');
    $state['admin_email'] = $email;
    return csrf_res(true, "Admin email changed to {$email}; a simple text/plain request smuggled JSON with no preflight.");
}

// Level 8 — naive Referer check that fails open when the header is absent
function csrf_h_l8(array $req, array &$state, bool $authed): array {
    if ($req['method'] !== 'POST') return csrf_res(false, 'change_email.php expects a POST here.');
    if (!$authed)                  return csrf_res(false, 'The admin session cookie was not sent.');
    if (!empty($req['referer_sent'])) {
        return csrf_res(false, 'Referer header present and cross-site (evil.attacker.example) — request blocked.');
    }
    // BUG: when the Referer is absent, the check "fails open" and allows the request.
    $email = trim((string)($req['params']['email'] ?? ''));
    if ($email === '')             return csrf_res(false, 'No email field in the POST body.');
    $state['admin_email'] = $email;
    return csrf_res(true, "Admin email changed to {$email}; a no-referrer request slipped past the naive Referer check.");
}

// Level 9 — double-submit cookie: attacker sets the cookie AND the body to the same value
function csrf_h_l9(array $req, array &$state, bool $authed): array {
    if ($req['method'] !== 'POST') return csrf_res(false, 'promote.php expects a POST here.');
    if (!$authed)                  return csrf_res(false, 'The admin session cookie was not sent.');
    $cookieTok = (string)($req['extra_cookies']['csrf_token'] ?? '');
    $bodyTok   = (string)($req['params']['csrf_token'] ?? '');
    if ($cookieTok === '' || $bodyTok === '') return csrf_res(false, 'Double-submit requires csrf_token in BOTH a cookie and the body.');
    if ($cookieTok !== $bodyTok)              return csrf_res(false, 'Double-submit mismatch: cookie token != body token.');
    // BUG: the server never checks the token is one IT issued — attacker sets both sides.
    $user = trim((string)($req['params']['user'] ?? ''));
    if ($user === '')              return csrf_res(false, 'No user specified to promote.');
    $state['target_role']   = 'admin';
    $state['promoted_user'] = $user;
    return csrf_res(true, "User '{$user}' promoted; an attacker-set cookie matched the body token (double-submit broken).");
}

// Level 10 — token + SameSite=Lax + Referer, with one uncovered GET path
function csrf_h_l10(array $req, array &$state, bool $authed): array {
    if ($req['method'] !== 'GET') return csrf_res(false, 'transfer_owner.php only accepts GET.');
    if (!$authed)                 return csrf_res(false, 'SameSite=Lax blocked the cookie — use a top-level GET navigation.');
    if (!empty($req['referer_sent'])) return csrf_res(false, 'Cross-site Referer present — blocked. Suppress it with a no-referrer policy.');
    $token = (string)($req['params']['csrf_token'] ?? '');
    if (!preg_match('/^[a-f0-9]{32}$/i', $token)) return csrf_res(false, 'csrf_token missing or malformed (needs 32 hex chars).');
    // Uncovered gap: token is format-only (not session-bound) + Lax sends the cookie on
    // top-level GET nav + the Referer check fails open when suppressed.
    $new = trim((string)($req['params']['new_owner'] ?? ''));
    if ($new === '')              return csrf_res(false, 'No new_owner specified.');
    $state['owner'] = $new;
    return csrf_res(true, "Account ownership transferred to '{$new}' — token, SameSite and Referer all bypassed via one GET.");
}

/* ============================================================
   Bot delivery — the victim opens the attacker's PoC
   ============================================================ */

/**
 * Deliver a PoC to the victim admin. Runs the level's real handler with the
 * admin session and records the outcome.
 *
 * @return array{ok: bool, reason: string, req: array, before: array, after: array}
 */
function csrf_deliver(int $level, string $poc): array {
    csrf_init_level($level);
    $before = $_SESSION['csrf'][$level];

    $parsed = csrf_parse_poc($poc);
    if (empty($parsed['found'])) {
        return [
            'ok'     => false,
            'reason' => 'No HTTP request found in your PoC. Include a URL, an <img>/<a>, a <form>, or a fetch() call.',
            'req'    => $parsed['req'],
            'before' => $before,
            'after'  => $before,
        ];
    }

    $state = $_SESSION['csrf'][$level];
    $res   = csrf_handle($level, $parsed['req'], $state);
    $_SESSION['csrf'][$level] = $state;
    if (!empty($res['ok'])) {
        $_SESSION['csrf'][$level]['solved'] = true;
    }

    return [
        'ok'     => !empty($res['ok']),
        'reason' => $res['reason'],
        'req'    => $parsed['req'],
        'before' => $before,
        'after'  => $_SESSION['csrf'][$level],
    ];
}

/** Human-readable summary of the request the bot reconstructed. */
function csrf_request_summary(array $req, int $level): string {
    $bits = [];
    $bits[] = 'Method: '   . ($req['method'] ?? '?');
    $bits[] = 'Endpoint: ' . (($req['target'] ?? '') !== '' ? $req['target'] : '(none)');
    $bits[] = 'Request kind: ' . ($req['kind'] ?? 'unknown');
    if (!empty($req['content_type'])) $bits[] = 'Content-Type: ' . $req['content_type'];
    $bits[] = 'admin_session cookie sent: ' . (csrf_cookie_sent($level, $req) ? 'yes' : 'no (SameSite=' . csrf_samesite($level) . ')');
    $bits[] = 'Referer sent: ' . (!empty($req['referer_sent']) ? 'yes (evil.attacker.example)' : 'no (suppressed)');
    if (!empty($req['extra_cookies'])) {
        $pairs = [];
        foreach ($req['extra_cookies'] as $k => $v) { $pairs[] = $k . '=' . $v; }
        $bits[] = 'Attacker-set cookies: ' . implode(', ', $pairs);
    }
    if (!empty($req['params'])) {
        $pairs = [];
        foreach ($req['params'] as $k => $v) {
            if (is_array($v)) $v = json_encode($v);
            $pairs[] = $k . '=' . $v;
        }
        $bits[] = 'Params: ' . implode(', ', $pairs);
    }
    if (($req['raw_body'] ?? '') !== '') {
        $bits[] = 'Body: ' . $req['raw_body'];
    }
    return implode("\n", $bits);
}
