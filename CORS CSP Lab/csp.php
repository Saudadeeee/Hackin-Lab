<?php
/**
 * CORS CSP Lab · a small, honest Content-Security-Policy evaluator.
 *
 * The CSP levels send a real Content-Security-Policy header from render.php,
 * so the learner's payload really does run (or really does not) in their
 * browser. This file answers the same question server-side, from the same
 * policy string, so a flag can be awarded for the *effect* rather than for a
 * payload matching a pattern.
 *
 * What it models (CSP Level 3, the parts these levels depend on):
 *
 *   - directive parsing and the default-src fallback
 *   - 'self', scheme-source, host-source with * wildcards and ports
 *   - 'unsafe-inline' and the rule that nonces or hashes make it inert
 *   - 'nonce-...' matching on the element, not on the URL
 *   - 'sha256-...' matching against the inline script's exact text
 *   - 'strict-dynamic': host allowlists ignored, parser-inserted scripts
 *     blocked, scripts inserted by an already-running script allowed
 *   - 'unsafe-eval' gating eval() / new Function()
 *   - base-uri: whether an injected <base href> is honoured, and what that
 *     does to every relative script URL on the page
 *
 * What it does not model: report-only mode, trusted-types, sandbox, redirects,
 * and the several directives these levels never touch. It is deliberately a
 * teaching model, and every verdict it prints names the directive it came from.
 */

/* =========================================================================
 * Policy parsing
 * ===================================================================== */

/**
 * "script-src 'self' https://cdn.example; object-src 'none'"
 *   => ['script-src' => ["'self'", 'https://cdn.example'], 'object-src' => ["'none'"]]
 */
function csp_parse(string $policy): array
{
    $out = [];
    foreach (explode(';', $policy) as $chunk) {
        $parts = preg_split('/\s+/', trim($chunk), -1, PREG_SPLIT_NO_EMPTY);
        if (!$parts) {
            continue;
        }
        $name = strtolower(array_shift($parts));
        if (!isset($out[$name])) {          // first occurrence wins, per spec
            $out[$name] = $parts;
        }
    }
    return $out;
}

/**
 * The source list that actually governs $directive, following the default-src
 * fallback. Returns null when nothing governs it (scripts unrestricted).
 */
function csp_effective(array $parsed, string $directive): ?array
{
    if (isset($parsed[$directive])) {
        return $parsed[$directive];
    }
    if (isset($parsed['default-src'])) {
        return $parsed['default-src'];
    }
    return null;
}

/** Case-insensitive keyword test, e.g. csp_has($src, "'strict-dynamic'"). */
function csp_has(?array $sources, string $keyword): bool
{
    if (!$sources) {
        return false;
    }
    foreach ($sources as $s) {
        if (strcasecmp($s, $keyword) === 0) {
            return true;
        }
    }
    return false;
}

/** Every nonce value declared in a source list (without the 'nonce-' wrapper). */
function csp_nonces(?array $sources): array
{
    $out = [];
    foreach ($sources ?? [] as $s) {
        if (preg_match("~^'nonce-(.+)'$~", $s, $m)) {
            $out[] = $m[1];
        }
    }
    return $out;
}

/** Every hash source declared, as ['algo' => 'sha256', 'b64' => '...']. */
function csp_hashes(?array $sources): array
{
    $out = [];
    foreach ($sources ?? [] as $s) {
        if (preg_match("~^'(sha256|sha384|sha512)-(.+)'$~i", $s, $m)) {
            $out[] = ['algo' => strtolower($m[1]), 'b64' => $m[2]];
        }
    }
    return $out;
}

/* =========================================================================
 * URLs
 * ===================================================================== */

/** "http://host:8095/a/b?q" => "http://host:8095" (default ports dropped). */
function csp_url_origin(string $url): string
{
    $p = parse_url($url);
    if (!is_array($p) || empty($p['scheme']) || empty($p['host'])) {
        return '';
    }
    $scheme = strtolower($p['scheme']);
    $origin = $scheme . '://' . strtolower($p['host']);
    $port   = $p['port'] ?? null;
    if ($port !== null && !(($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443))) {
        $origin .= ':' . $port;
    }
    return $origin;
}

/** RFC 3986 remove_dot_segments. */
function csp_remove_dots(string $path): string
{
    $out = [];
    foreach (explode('/', $path) as $seg) {
        if ($seg === '.') {
            continue;
        }
        if ($seg === '..') {
            array_pop($out);
            continue;
        }
        $out[] = $seg;
    }
    $res = implode('/', $out);
    // Preserve a trailing slash that "." or ".." consumed.
    if (preg_match('~(^|/)(\.|\.\.)$~', $path) && substr($res, -1) !== '/') {
        $res .= '/';
    }
    return $res;
}

/** Resolve a possibly relative reference against an absolute base URL. */
function csp_resolve(string $base, string $rel): string
{
    $rel = trim($rel);
    if ($rel === '') {
        return $base;
    }
    if (preg_match('~^[a-z][a-z0-9+.\-]*:~i', $rel)) {   // already absolute
        return $rel;
    }
    $b = parse_url($base);
    if (!is_array($b) || empty($b['scheme'])) {
        return $rel;
    }
    $scheme = $b['scheme'];
    $auth   = ($b['host'] ?? '') . (isset($b['port']) ? ':' . $b['port'] : '');

    if (str_starts_with($rel, '//')) {                   // protocol-relative
        return $scheme . ':' . $rel;
    }
    if (str_starts_with($rel, '/')) {                    // root-relative
        return $scheme . '://' . $auth . csp_remove_dots($rel);
    }
    if (str_starts_with($rel, '?') || str_starts_with($rel, '#')) {
        return $scheme . '://' . $auth . ($b['path'] ?? '/') . $rel;
    }
    $dir = $b['path'] ?? '/';
    $dir = substr($dir, 0, strrpos($dir, '/') !== false ? strrpos($dir, '/') + 1 : 0);
    if ($dir === '') {
        $dir = '/';
    }
    return $scheme . '://' . $auth . csp_remove_dots($dir . $rel);
}

/**
 * Does one source expression match one URL?
 * Handles 'self', *, scheme-source, and host-source with wildcard and port.
 */
function csp_source_matches(string $source, string $url, string $pageOrigin): bool
{
    $source = trim($source);
    if ($source === '') {
        return false;
    }
    if ($source === '*') {
        $s = strtolower((string)parse_url($url, PHP_URL_SCHEME));
        return in_array($s, ['http', 'https', 'ws', 'wss', 'ftp'], true);
    }
    if (strcasecmp($source, "'self'") === 0) {
        return csp_url_origin($url) === $pageOrigin;
    }
    if (str_starts_with($source, "'")) {
        return false;   // any other keyword source never matches a URL
    }
    if (preg_match('~^([a-z][a-z0-9+.\-]*):$~i', $source, $m)) {   // scheme-source
        return strcasecmp((string)parse_url($url, PHP_URL_SCHEME), $m[1]) === 0;
    }

    // host-source: [scheme "://"] host [":" port] [path]
    if (!preg_match('~^(?:([a-z][a-z0-9+.\-]*)://)?([^/:]+)(?::(\d+|\*))?(/.*)?$~i', $source, $m)) {
        return false;
    }
    [, $sScheme, $sHost, $sPort, $sPath] = array_pad($m, 5, '');

    $u = parse_url($url);
    if (!is_array($u) || empty($u['host'])) {
        return false;
    }
    $uScheme = strtolower($u['scheme'] ?? '');
    $uHost   = strtolower($u['host']);
    $uPort   = $u['port'] ?? ($uScheme === 'https' ? 443 : ($uScheme === 'http' ? 80 : null));
    $uPath   = $u['path'] ?? '/';

    if ($sScheme !== '') {
        if (strcasecmp($sScheme, $uScheme) !== 0) {
            return false;
        }
    } elseif ($uScheme === 'http') {
        // A source without a scheme allows http and its secure upgrade.
    } elseif ($uScheme !== 'https') {
        return false;
    }

    $sHost = strtolower($sHost);
    if (str_starts_with($sHost, '*.')) {
        $suffix = substr($sHost, 1);              // ".example.com"
        if (!str_ends_with($uHost, $suffix)) {
            return false;
        }
    } elseif ($sHost !== $uHost) {
        return false;
    }

    if ($sPort !== '' && $sPort !== '*') {
        if ((int)$sPort !== (int)$uPort) {
            return false;
        }
    } elseif ($sPort === '' && $sScheme !== '') {
        $default = $sScheme === 'https' ? 443 : ($sScheme === 'http' ? 80 : null);
        if ($default !== null && (int)$uPort !== $default) {
            return false;
        }
    }

    if ($sPath !== '' && $sPath !== '/') {
        if (str_ends_with($sPath, '/')) {
            if (!str_starts_with($uPath, $sPath)) {
                return false;
            }
        } elseif ($uPath !== $sPath) {
            return false;
        }
    }
    return true;
}

/* =========================================================================
 * Markup scanning
 * ===================================================================== */

/**
 * Parse the injected markup the way a browser's HTML parser would, and report
 * the pieces CSP cares about.
 *
 * @return array{scripts:array, base:?string, handlers:array, gadget_hosts:array, parse_ok:bool}
 */
function csp_scan_markup(string $markup): array
{
    $res = ['scripts' => [], 'base' => null, 'handlers' => [], 'gadget_hosts' => [], 'parse_ok' => true];
    if (trim($markup) === '') {
        return $res;
    }

    $prev = libxml_use_internal_errors(true);
    $doc  = new DOMDocument();
    $ok   = $doc->loadHTML(
        '<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>' . $markup . '</body></html>',
        LIBXML_NONET
    );
    libxml_clear_errors();
    libxml_use_internal_errors($prev);
    if (!$ok) {
        $res['parse_ok'] = false;
        return $res;
    }

    $xp = new DOMXPath($doc);

    foreach ($xp->query('//script') as $s) {
        /** @var DOMElement $s */
        $src = $s->getAttribute('src');
        $res['scripts'][] = [
            'kind'  => $src !== '' ? 'external' : 'inline',
            'src'   => $src,
            'nonce' => $s->getAttribute('nonce'),
            'text'  => $s->textContent,
        ];
    }

    $base = $xp->query('//base[@href]')->item(0);
    if ($base instanceof DOMElement) {
        $res['base'] = $base->getAttribute('href');
    }

    foreach ($xp->query('//*') as $el) {
        /** @var DOMElement $el */
        if (!$el->hasAttributes()) {
            continue;
        }
        foreach ($el->attributes as $attr) {
            $n = strtolower($attr->nodeName);
            if (str_starts_with($n, 'on') && $attr->nodeValue !== '') {
                $res['handlers'][] = ['element' => $el->nodeName, 'attr' => $n, 'code' => $attr->nodeValue];
            }
            if ($n === 'data-main' && $attr->nodeValue !== '') {
                $res['gadget_hosts'][] = ['element' => $el->nodeName, 'value' => $attr->nodeValue];
            }
        }
    }
    return $res;
}

/* =========================================================================
 * The decision
 * ===================================================================== */

/**
 * Decide whether one script would run.
 *
 * @param array $el ['kind'=>'inline'|'external', 'src'=>, 'nonce'=>, 'text'=>,
 *                   'inserted'=>'parser'|'script']
 * @return array{allowed:bool, reason:string, directive:string}
 */
function csp_script_allowed(?array $sources, array $el, string $pageOrigin, string $documentBase): array
{
    if ($sources === null) {
        return ['allowed' => true, 'directive' => '(none)',
                'reason' => 'No script-src and no default-src, so nothing restricts scripts on this page.'];
    }
    if (csp_has($sources, "'none'")) {
        return ['allowed' => false, 'directive' => "'none'",
                'reason' => "The source list is 'none', which matches nothing."];
    }

    $nonces   = csp_nonces($sources);
    $hashes   = csp_hashes($sources);
    $inserted = $el['inserted'] ?? 'parser';
    $elNonce  = (string)($el['nonce'] ?? '');

    /* ---- inline scripts -------------------------------------------- */
    if (($el['kind'] ?? 'inline') === 'inline') {
        if ($elNonce !== '' && in_array($elNonce, $nonces, true)) {
            return ['allowed' => true, 'directive' => "'nonce-" . $elNonce . "'",
                    'reason' => 'The element carries a nonce attribute that matches a nonce source in the policy.'];
        }
        foreach ($hashes as $h) {
            $digest = base64_encode(hash($h['algo'], (string)($el['text'] ?? ''), true));
            if (hash_equals($h['b64'], $digest)) {
                return ['allowed' => true, 'directive' => "'" . $h['algo'] . '-' . $h['b64'] . "'",
                        'reason' => 'The hash of this exact script text matches a hash source in the policy.'];
            }
        }
        if (csp_has($sources, "'unsafe-inline'")) {
            if ($nonces || $hashes) {
                return ['allowed' => false, 'directive' => "'unsafe-inline'",
                        'reason' => "'unsafe-inline' is present but the policy also declares nonces or hashes, "
                                  . 'which makes it inert for browsers that understand them.'];
            }
            return ['allowed' => true, 'directive' => "'unsafe-inline'",
                    'reason' => "'unsafe-inline' allows any inline script."];
        }
        if ($elNonce !== '') {
            return ['allowed' => false, 'directive' => 'script-src',
                    'reason' => 'The element has a nonce attribute, but its value is not one of the nonces this policy declared.'];
        }
        return ['allowed' => false, 'directive' => 'script-src',
                'reason' => "Inline script with no nonce and no matching hash, and 'unsafe-inline' is not present."];
    }

    /* ---- external scripts ------------------------------------------- */
    $url = csp_resolve($documentBase, (string)($el['src'] ?? ''));

    if ($elNonce !== '' && in_array($elNonce, $nonces, true)) {
        return ['allowed' => true, 'directive' => "'nonce-" . $elNonce . "'",
                'reason' => 'The nonce travels on the element, not on the URL, so this loads from ' . csp_url_origin($url) . '.'];
    }
    if (csp_has($sources, "'strict-dynamic'")) {
        if ($inserted === 'script') {
            return ['allowed' => true, 'directive' => "'strict-dynamic'",
                    'reason' => 'Inserted by a script that was itself allowed. Under strict-dynamic that trust propagates, '
                              . 'and host allowlists are not consulted.'];
        }
        return ['allowed' => false, 'directive' => "'strict-dynamic'",
                'reason' => 'strict-dynamic makes the browser ignore every host source, and this element was written by the '
                          . 'HTML parser rather than inserted by an already-trusted script.'];
    }
    foreach ($sources as $s) {
        // csp_source_matches() understands 'self' and rejects every other
        // keyword source, so the whole list can be walked here.
        if (csp_source_matches($s, $url, $pageOrigin)) {
            return ['allowed' => true, 'directive' => $s,
                    'reason' => 'The resolved URL ' . $url . ' matches the source ' . $s . '.'];
        }
    }
    return ['allowed' => false, 'directive' => 'script-src',
            'reason' => 'No source in the list matches ' . ($url === '' ? '(empty src)' : $url) . '.'];
}

/**
 * Full evaluation of one injection against one policy.
 *
 * @param string $policy the exact header value render.php sends
 * @param string $markup the attacker-controlled markup
 * @param array  $ctx    [
 *   'page_url'     => absolute URL of the page the markup lands in,
 *   'page_scripts' => the page's own <script> elements,
 *                     [['label'=>, 'src'=>, 'nonce'=>, 'kind'=>'external']],
 *   'loader'       => true when the page ships loader.js (the data-main gadget),
 * ]
 * @return array
 */
function csp_evaluate(string $policy, string $markup, array $ctx): array
{
    $parsed     = csp_parse($policy);
    $sources    = csp_effective($parsed, 'script-src');
    $pageUrl    = (string)($ctx['page_url'] ?? 'http://localhost/render.php');
    $pageOrigin = csp_url_origin($pageUrl);
    $scan       = csp_scan_markup($markup);

    /* -- 1. does an injected <base href> take effect? ------------------ */
    $baseInfo = ['injected' => $scan['base'], 'honored' => false, 'reason' => ''];
    $docBase  = $pageUrl;
    if ($scan['base'] !== null) {
        if (isset($parsed['base-uri'])) {
            $allowed = false;
            foreach ($parsed['base-uri'] as $s) {
                if (strcasecmp($s, "'self'") === 0) {
                    $allowed = csp_url_origin(csp_resolve($pageUrl, $scan['base'])) === $pageOrigin;
                } elseif (!str_starts_with($s, "'")) {
                    $allowed = csp_source_matches($s, csp_resolve($pageUrl, $scan['base']), $pageOrigin);
                }
                if ($allowed) {
                    break;
                }
            }
            $baseInfo['honored'] = $allowed;
            $baseInfo['reason']  = $allowed
                ? 'base-uri is declared and this href satisfies it.'
                : 'base-uri is declared and this href does not satisfy it, so the browser ignores the element.';
        } else {
            $baseInfo['honored'] = true;
            $baseInfo['reason']  = 'The policy declares no base-uri directive, so the injected <base> is honoured and '
                                 . 'becomes the document base for every relative URL below it.';
        }
        if ($baseInfo['honored']) {
            $docBase = csp_resolve($pageUrl, $scan['base']);
        }
    }

    /* -- 2. collect every script the browser would consider ------------ */
    $candidates = [];

    foreach ($ctx['page_scripts'] ?? [] as $ps) {
        $candidates[] = [
            'label'    => $ps['label'] ?? "the page's own script",
            'kind'     => $ps['kind'] ?? 'external',
            'src'      => $ps['src'] ?? '',
            'nonce'    => $ps['nonce'] ?? '',
            'text'     => $ps['text'] ?? '',
            'inserted' => 'parser',
            'origin_of'=> 'page',
        ];
    }
    foreach ($scan['scripts'] as $i => $s) {
        $candidates[] = [
            'label'    => 'injected <script> #' . ($i + 1) . ($s['kind'] === 'external' ? ' (src)' : ' (inline)'),
            'kind'     => $s['kind'],
            'src'      => $s['src'],
            'nonce'    => $s['nonce'],
            'text'     => $s['text'],
            'inserted' => 'parser',
            'origin_of'=> 'injection',
        ];
    }
    foreach ($scan['handlers'] as $h) {
        $candidates[] = [
            'label'    => 'injected ' . $h['attr'] . ' handler on <' . strtolower($h['element']) . '>',
            'kind'     => 'inline',
            'src'      => '',
            'nonce'    => '',           // event handlers cannot carry a nonce
            'text'     => $h['code'],
            'inserted' => 'parser',
            'origin_of'=> 'injection',
            'handler'  => true,
        ];
    }
    // The shipped loader gadget: it runs with a valid nonce and copies the
    // data-main attribute straight into a script src, exactly as loader.js does.
    if (!empty($ctx['loader'])) {
        foreach ($scan['gadget_hosts'] as $g) {
            $candidates[] = [
                'label'    => 'loader.js sees data-main="' . $g['value'] . '" and inserts a script',
                'kind'     => 'external',
                'src'      => $g['value'],
                'nonce'    => '',
                'text'     => '',
                'inserted' => 'script',
                'origin_of'=> 'gadget',
            ];
        }
    }

    /* -- 3. decide each one -------------------------------------------- */
    $findings = [];
    foreach ($candidates as $c) {
        $el = $c;
        // An inline event handler is never covered by a nonce, even if one exists.
        if (!empty($c['handler'])) {
            $el['nonce'] = '';
        }
        $verdict = csp_script_allowed($sources, $el, $pageOrigin, $docBase);
        $url     = $c['kind'] === 'external' ? csp_resolve($docBase, (string)$c['src']) : '';
        $findings[] = [
            'label'     => $c['label'],
            'kind'      => $c['kind'],
            'url'       => $url,
            'origin'    => $url !== '' ? csp_url_origin($url) : '',
            'offorigin' => $url !== '' && csp_url_origin($url) !== $pageOrigin,
            'source'    => $c['origin_of'],
            'inserted'  => $c['inserted'],
            'allowed'   => $verdict['allowed'],
            'directive' => $verdict['directive'],
            'reason'    => $verdict['reason'],
        ];
    }

    return [
        'policy'      => $policy,
        'parsed'      => $parsed,
        'sources'     => $sources,
        'page_url'    => $pageUrl,
        'page_origin' => $pageOrigin,
        'document_base' => $docBase,
        'base'        => $baseInfo,
        'scan'        => $scan,
        'findings'    => $findings,
        'unsafe_eval' => csp_has($sources, "'unsafe-eval'"),
    ];
}

/** Findings that actually run, optionally filtered to attacker-controlled ones. */
function csp_executed(array $eval, ?string $source = null): array
{
    $out = [];
    foreach ($eval['findings'] as $f) {
        if (!$f['allowed']) {
            continue;
        }
        if ($source !== null && $f['source'] !== $source) {
            continue;
        }
        $out[] = $f;
    }
    return $out;
}

/* =========================================================================
 * Rendering the evaluation as pipeline stages
 * ===================================================================== */

/**
 * Turn an evaluation into lk_pipeline() stages, so the learner sees which
 * directive made the decision rather than a yes/no.
 */
function csp_stages(array $eval): array
{
    $stages = [];

    $stages[] = [
        'label' => 'Content-Security-Policy (the header render.php really sent)',
        'value' => $eval['policy'],
        'note'  => 'Open the frame in a new tab and read the response headers if you want to confirm it.',
    ];

    $stages[] = [
        'label' => 'effective script-src (after the default-src fallback)',
        'value' => $eval['sources'] === null ? '(nothing governs scripts)' : implode(' ', $eval['sources']),
        'note'  => $eval['sources'] === null
            ? 'Neither script-src nor default-src is present.'
            : 'Every decision below is made against this list and nothing else.',
    ];

    if ($eval['base']['injected'] !== null) {
        $stages[] = [
            'label'   => 'injected <base href>',
            'value'   => (string)$eval['base']['injected'],
            // Reasons are plain prose and may quote attacker-supplied URLs, so
            // they are escaped before being placed in the note, which is HTML.
            'note'    => lk_esc($eval['base']['reason']) . ' Document base is now <code>'
                       . lk_esc($eval['document_base']) . '</code>.',
            'verdict' => $eval['base']['honored'] ? 'pass' : 'block',
        ];
    }

    $scan  = $eval['scan'];
    $found = [];
    if ($scan['scripts']) {
        $found[] = count($scan['scripts']) . ' <script> element(s)';
    }
    if ($scan['handlers']) {
        $found[] = count($scan['handlers']) . ' inline event handler(s)';
    }
    if ($scan['gadget_hosts']) {
        $found[] = count($scan['gadget_hosts']) . ' element(s) with data-main';
    }
    if ($scan['base'] !== null) {
        $found[] = '1 <base> element';
    }
    $summary = $found ? implode(', ', $found) : 'no script-bearing nodes';
    $stages[] = [
        'label' => 'HTML parse of your markup',
        'value' => $summary,
        'note'  => $found
            ? 'Parsed with a real HTML parser rather than a pattern match, so what is listed here is what a browser '
            . 'would build from your bytes.'
            : 'Nothing in the markup can become script, so CSP never gets a chance to have an opinion.',
    ];

    foreach ($eval['findings'] as $f) {
        $stages[] = [
            'label'   => $f['label'],
            'value'   => $f['kind'] === 'external'
                ? ($f['url'] !== '' ? $f['url'] : '(empty src)')
                : 'inline code',
            'note'    => lk_esc($f['reason'])
                       . ($f['offorigin'] ? ' <strong>This is a different origin from the page.</strong>' : ''),
            'verdict' => $f['allowed'] ? 'pass' : 'block',
        ];
    }

    return $stages;
}
