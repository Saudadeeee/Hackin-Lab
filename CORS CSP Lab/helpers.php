<?php
/**
 * CORS CSP Lab · lab metadata, flags, hints and the shared level UI.
 */

require_once __DIR__ . '/lab_kit.php';
require_once __DIR__ . '/cors.php';
require_once __DIR__ . '/csp.php';
require_once __DIR__ . '/jsexpr.php';

function bp_lab(): array
{
    return [
        'slug'    => 'browserpolicy',
        'name'    => 'CORS & CSP Lab',
        'icon'    => 'ORIGIN',
        'total'   => 10,
        'tagline' => 'Two browser policies, and the ten ways they are written wrong',
    ];
}

function bp_flag(int $level): string
{
    $flags = [
        1  => 'FLAG{reflecting_the_origin_is_not_an_allowlist}',
        2  => 'FLAG{null_is_an_origin_anyone_can_send}',
        3  => 'FLAG{anchor_both_ends_of_the_origin}',
        4  => 'FLAG{ends_with_is_not_a_subdomain_check}',
        5  => 'FLAG{the_wildcard_inherits_the_weakest_host}',
        6  => 'FLAG{jsonp_turns_self_into_unsafe_inline}',
        7  => 'FLAG{a_reused_nonce_is_only_a_password}',
        8  => 'FLAG{base_uri_rewrote_every_relative_script}',
        9  => 'FLAG{unsafe_eval_needs_no_script_tag}',
        10 => 'FLAG{strict_dynamic_trusts_whatever_the_loader_loads}',
    ];
    return $flags[$level] ?? '';
}

function bp_levels(): array
{
    return [
        1 => [
            'title'      => 'Reflected Origin with Credentials',
            'difficulty' => 'Easy',
            'skill'      => 'Access-Control-Allow-Origin, credentials, why reflection is not an allowlist',
            'desc'       => 'The API copies the request <code>Origin</code> into <code>Access-Control-Allow-Origin</code> and allows credentials. Every origin is on the allowlist, including yours.',
        ],
        2 => [
            'title'      => 'The null Origin',
            'difficulty' => 'Easy',
            'skill'      => 'Where Origin: null comes from and why it cannot be trusted',
            'desc'       => 'The allowlist is a real allowlist. One of its three entries is the literal string <code>null</code>, which any sandboxed iframe can send.',
        ],
        3 => [
            'title'      => 'Prefix Match',
            'difficulty' => 'Medium',
            'skill'      => 'Unanchored regular expressions on origins',
            'desc'       => 'The origin is matched with a regex anchored at the start and nowhere else. A domain that begins with the trusted one is still a domain you can register.',
        ],
        4 => [
            'title'      => 'Suffix Match',
            'difficulty' => 'Medium',
            'skill'      => 'str_ends_with on an origin, and the missing dot',
            'desc'       => 'The other half of the same mistake: the check anchors the end and forgets the separator, so a longer label in front still passes.',
        ],
        5 => [
            'title'      => 'Wildcard Subdomain plus a Weak Link',
            'difficulty' => 'Hard',
            'skill'      => 'Inherited trust: an allowlist is only as strong as every host in it',
            'desc'       => 'The wildcard check is written correctly. One host inside the wildcard reflects a query parameter into HTML without escaping, and that is enough.',
        ],
        6 => [
            'title'      => 'CSP with a JSONP Gadget',
            'difficulty' => 'Medium',
            'skill'      => "'self' allowlists an origin, not a file",
            'desc'       => 'No <code>unsafe-inline</code>, so inline script is dead. The origin still hosts a JSONP endpoint that returns whatever callback name you ask for.',
        ],
        7 => [
            'title'      => 'Predictable Nonce',
            'difficulty' => 'Hard',
            'skill'      => 'A nonce is only safe if it is unpredictable and used once',
            'desc'       => 'The nonce comes from <code>mt_rand()</code> seeded with the date, so every response today carries the same value and tomorrow&rsquo;s is computable now.',
        ],
        8 => [
            'title'      => 'Missing base-uri',
            'difficulty' => 'Hard',
            'skill'      => 'The nonce rides on the element, not on the URL',
            'desc'       => 'A properly random nonce, and no <code>base-uri</code> directive. An injected <code>&lt;base href&gt;</code> moves every relative script to a host of your choosing.',
        ],
        9 => [
            'title'      => 'unsafe-eval Gadget',
            'difficulty' => 'Expert',
            'skill'      => 'String-to-code sinks that no script tag is involved in',
            'desc'       => 'A client-side templating helper hands the text between <code>${</code> and <code>}</code> to <code>new Function()</code>. The policy permits that. The filter is a denylist.',
        ],
        10 => [
            'title'      => 'strict-dynamic and the Script Gadget',
            'difficulty' => 'Expert',
            'skill'      => 'Propagated trust, and why a loader is part of your policy',
            'desc'       => 'Under <code>strict-dynamic</code> a trusted script&rsquo;s own DOM insertions run. The page ships a loader that turns an attribute into a script URL.',
        ],
    ];
}

/* =========================================================================
 * Hints: concept -> observation about THIS code -> technique -> shape -> payload
 * ===================================================================== */

function bp_hints(int $level): array
{
    $alt = bp_alt_origin();
    $h = [
        1 => [
            'The browser attaches <code>Origin</code> to cross-origin requests and then asks the response one question: does <code>Access-Control-Allow-Origin</code> name me? The <em>server</em> owns that decision.',
            'Read the source panel and look for a comparison. There is no <code>in_array</code>, no regex, no equality test. Line 5 copies the request header into the response header.',
            'Send an <code>Origin</code> the company has never heard of and read the two headers that come back. If your origin is echoed, the allowlist is "whoever asks".',
            'The value is a scheme and a host with no path and no trailing slash: <code>https://host.tld</code>.',
            'Put <code>https://attacker.test</code> in the Origin box and send the request.',
        ],
        2 => [
            '<code>null</code> is a real value of the <code>Origin</code> header, not an absence. A document in an <em>opaque origin</em> has no origin to name, so the browser serialises it as the four letters <code>null</code>.',
            'The allowlist on lines 3&ndash;7 is a correct <code>in_array</code> comparison. The bug is not the comparison, it is the third entry.',
            'Documents get an opaque origin from <code>&lt;iframe sandbox="allow-scripts"&gt;</code> without <code>allow-same-origin</code>, from <code>data:</code> URLs, from local files, and after some cross-origin redirects. All of those are reachable by an attacker page.',
            'The Origin you need is not a URL at all. It is the bare word.',
            'Send <code>null</code> as the Origin.',
        ],
        3 => [
            'An origin comparison has exactly two safe forms: string equality against a full origin, or parse the origin and compare the host exactly. Anything else is a substring test wearing a costume.',
            'The pattern is <code>~^https?://portal\\.hackinlab\\.internal~</code>. The <code>^</code> anchors the start. Now look for what anchors the end.',
            'Hostnames are read right to left by DNS. Everything to the left of the registrable domain is a label the domain owner controls; everything to the right is somebody else&rsquo;s. Append, do not prepend.',
            'Shape: the whole trusted origin, then more label, then a domain you can register.',
            'Send <code>https://portal.hackinlab.internal.evil.test</code>.',
        ],
        4 => [
            'Level 3 forgot the end anchor. This one forgets the start. Both are the same class of bug: an origin was treated as text instead of as a parsed structure.',
            '<code>str_ends_with($origin, \'hackinlab.internal\')</code> looks at the last 18 characters of the whole origin string, scheme included. It never requires a <code>.</code> in front of them.',
            'If the separator is not checked, put a letter there instead. The suffix still matches, and the registrable domain is now yours.',
            'Shape: <code>https://</code> + any word + <code>hackinlab.internal</code>, with no dot between the word and the domain.',
            'Send <code>https://evilhackinlab.internal</code>.',
        ],
        5 => [
            'A <code>*.domain</code> allowlist is inherited trust. It says "any host under this domain may read our data with the user&rsquo;s cookies", which makes every one of those hosts part of the API&rsquo;s attack surface.',
            'This check is written correctly: it parses the origin, requires an http/https scheme, and requires the host to be the domain or to end with a dot and the domain. There is no string trick to find here.',
            'So attack the allowlist&rsquo;s membership instead. <a href="legacy.php?note=hello" target="_blank">legacy.php</a> runs on <code>legacy.hackinlab.internal</code>, which the wildcard accepts, and it prints the <code>note</code> parameter into the page without escaping it.',
            'You need two things to be true at once: an origin the wildcard admits, and a real script node in the legacy page&rsquo;s output built from your parameter.',
            'Origin: <code>http://legacy.hackinlab.internal</code>. Note: <code>&lt;script&gt;fetch(\'/api.php?level=5\',{credentials:\'include\'})&lt;/script&gt;</code>',
        ],
        6 => [
            "<code>'self'</code> allowlists an <em>origin</em>. Not a directory, not a file. Every endpoint your origin has ever shipped is inside it, including the ones nobody remembers.",
            'The policy has no <code>unsafe-inline</code>, so <code>&lt;script&gt;code&lt;/script&gt;</code> is dead on arrival. Read it again and notice what it still permits: <code>&lt;script src&gt;</code> pointing anywhere on this origin.',
            'A JSONP endpoint takes a callback name from the query string and returns <code>callbackName({...})</code> with a JavaScript content type. The callback name is the first token of a script the browser will execute.',
            'Shape: <code>&lt;script src="/jsonp.php?callback=YOUR_CODE"&gt;&lt;/script&gt;</code>. The endpoint still appends <code>({...});</code> after your text, so end your code in a way that makes the rest harmless &mdash; a line comment does it.',
            'Inject <code>&lt;script src="/jsonp.php?callback=hlab.win()//"&gt;&lt;/script&gt;</code>.',
        ],
        7 => [
            'A nonce is a one-time ticket the server prints on both the header and the tag. It works only while two things hold: an attacker cannot guess it, and it is never reused on a second response.',
            'Line 3 is <code>mt_srand((int)(time() / 86400))</code>. That seeds the generator with a day counter, so every response served today produces the same nonce, and tomorrow&rsquo;s is computable today.',
            'You do not have to predict anything here. The nonce is printed in the <code>Content-Security-Policy</code> header of a response you already hold, and it will still be valid for the rest of the day.',
            'Shape: an inline script that carries the nonce as an attribute, <code>&lt;script nonce="…"&gt;…&lt;/script&gt;</code>.',
            'Copy the nonce out of the policy shown on this page and inject <code>&lt;script nonce="THE_NONCE"&gt;hlab.win()&lt;/script&gt;</code>.',
        ],
        8 => [
            '<code>&lt;base href&gt;</code> sets the document base URL. Every relative URL below it resolves against that base &mdash; images, links, and script <code>src</code> attributes alike.',
            'The policy here is <code>script-src \'nonce-…\'; object-src \'none\'</code>. The nonce is properly random and changes on every response, so guessing it is out. Note what the policy does <em>not</em> contain: a <code>base-uri</code> directive.',
            'Look at the page&rsquo;s own tag: <code>&lt;script nonce="…" src="app/widget.js"&gt;</code>. That path is relative. And the nonce is an attribute of the element, not a property of the URL, so it stays valid wherever the URL ends up pointing.',
            'Shape: a <code>&lt;base&gt;</code> element with an <code>href</code> on an origin you control, injected above the script tag.',
            'Inject <code>&lt;base href="' . lk_esc($alt) . '/attacker/"&gt;</code>. Note that <code>127.0.0.1</code> and <code>localhost</code> are different origins to a browser even when the same server answers both.',
        ],
        9 => [
            "<code>'unsafe-eval'</code> changes nothing about which scripts may load. It permits script that is <em>already running</em> to turn strings into code through <code>eval</code>, <code>new Function</code>, and <code>setTimeout('...')</code>. No new <code>&lt;script&gt;</code> tag is involved, which is why a strict allowlist can sit next to it and look fine.",
            'Read <a href="tmpl.js" target="_blank">tmpl.js</a>. It pulls every <code>${...}</code> out of the template with its own regex, runs two checks on the text, then calls <code>new Function(\'d\', \'return (\' + expr + \')\')</code>.',
            'The first check is a character allowlist, the second a substring denylist. A denylist over an expression language loses to computed property access: a name you never spell cannot be found in your text.',
            'Shape: start from a value the sandbox hands you, reach the <code>Function</code> constructor, call it with source, then call the result. In JavaScript <code>\'\'.constructor</code> is <code>String</code>, and any function&rsquo;s <code>.constructor</code> is <code>Function</code>.',
            'Template: <code>${\'\'[\'con\'+\'structor\'][\'con\'+\'structor\'](\'hlab.win()\')()}</code>',
        ],
        10 => [
            "<code>'strict-dynamic'</code> tells the browser to ignore every host and scheme source in the list and instead trust whatever an already-trusted script inserts into the DOM. The trust boundary moves from URLs to code.",
            'Two consequences follow, and both are in the trace: a <code>&lt;script&gt;</code> written by the HTML parser needs the nonce and will not get it, while a script created by <code>loader.js</code> and appended to the document runs no matter where it points.',
            'Read <a href="loader.js" target="_blank">loader.js</a>. It runs with a valid nonce, finds the first element carrying <code>data-main</code>, and assigns that attribute straight to <code>script.src</code> &mdash; the same shape RequireJS has shipped for years.',
            'So you need neither a script tag nor the nonce. You need markup the loader will pick up: any element with a <code>data-main</code> attribute pointing at a URL you control.',
            'Inject <code>&lt;div data-main="' . lk_esc($alt) . '/attacker/widget.js"&gt;&lt;/div&gt;</code>.',
        ],
    ];
    return $h[$level] ?? [];
}

/* =========================================================================
 * Origins and policies
 * ===================================================================== */

/** The origin this lab is being served from, as the browser sees it. */
function bp_self_origin(): string
{
    $https  = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    $scheme = $https ? 'https' : 'http';
    $host   = $_SERVER['HTTP_HOST'] ?? 'localhost';
    return $scheme . '://' . $host;
}

/**
 * A second origin on the same server, reachable from the same browser.
 * localhost and 127.0.0.1 are distinct origins, which is what levels 8 and 10
 * need in order to demonstrate an off-origin load without external DNS.
 */
function bp_alt_origin(): string
{
    $origin = bp_self_origin();
    $p      = parse_url($origin);
    $host   = strtolower($p['host'] ?? 'localhost');
    $port   = isset($p['port']) ? ':' . $p['port'] : '';
    $other  = ($host === 'localhost' || $host === '::1') ? '127.0.0.1' : 'localhost';
    return ($p['scheme'] ?? 'http') . '://' . $other . $port;
}

/** Level 7's nonce: the same recipe the source panel shows. */
function bp_daily_nonce(int $dayOffset = 0): string
{
    mt_srand((int)(time() / 86400) + $dayOffset);
    return dechex(mt_rand());
}

/** A nonce that is actually unpredictable, used by levels 8 and 10. */
function bp_random_nonce(): string
{
    return bin2hex(random_bytes(9));
}

/**
 * The Content-Security-Policy for one level. render.php sends exactly this
 * string as a header; the level pages evaluate exactly this string. There is
 * no second copy anywhere.
 */
function bp_policy(int $level, string $nonce = ''): string
{
    switch ($level) {
        case 6:
            return "default-src 'self'; script-src 'self' https://cdn.hackinlab.internal; object-src 'none'";
        case 7:
            return "default-src 'self'; script-src 'nonce-" . $nonce . "'; object-src 'none'";
        case 8:
            return "default-src 'self'; script-src 'nonce-" . $nonce . "'; object-src 'none'";
        case 9:
            return "default-src 'self'; script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'self'";
        case 10:
            return "default-src 'self'; script-src 'nonce-" . $nonce . "' 'strict-dynamic'; object-src 'none'; base-uri 'self'";
        default:
            return '';
    }
}

/* =========================================================================
 * Making real requests from the level pages
 * ===================================================================== */

/**
 * Perform a real HTTP request and return the real response.
 *
 * @param string[] $headers extra request header lines
 * @return array{ok:bool, status:string, raw:string[], map:array, body:string, error:string}
 */
function bp_http(string $url, array $headers = [], int $timeout = 6): array
{
    $ctx = stream_context_create(['http' => [
        'method'        => 'GET',
        'header'        => $headers ? implode("\r\n", $headers) . "\r\n" : '',
        'timeout'       => $timeout,
        'ignore_errors' => true,
        'follow_location' => 0,
    ]]);

    $body = @file_get_contents($url, false, $ctx);
    $raw  = $http_response_header ?? [];

    if ($body === false && !$raw) {
        return ['ok' => false, 'status' => '', 'raw' => [], 'map' => [], 'body' => '',
                'error' => 'The request to ' . $url . ' did not complete.'];
    }
    return ['ok' => true, 'status' => $raw[0] ?? '', 'raw' => $raw,
            'map' => cors_header_map($raw), 'body' => (string)$body, 'error' => ''];
}

/** Strip anything that would let a header value break out of its own line. */
function bp_single_line(string $s): string
{
    return trim(str_replace(["\r", "\n", "\0"], '', $s));
}

/**
 * The address the level pages use to reach the app from inside the container.
 * It is not the origin your browser uses - the published port only exists
 * outside - so the loopback address is the reliable one here.
 */
function bp_internal_base(): string
{
    return 'http://127.0.0.1';
}

/**
 * The URL of the frame as the browser sees it. The CSP evaluation resolves
 * relative script URLs against this, so it has to be the browser's view of the
 * page rather than the container's loopback address.
 */
function bp_render_url(int $level): string
{
    return bp_self_origin() . '/render.php?level=' . $level;
}

/**
 * Turn a same-origin URL the evaluator produced into one this process can
 * actually fetch. The published port only exists outside the container, so a
 * URL on our own origin has to be re-addressed to loopback before use.
 * Returns null for URLs that are not on our origin.
 */
function bp_reachable(string $url): ?string
{
    if (csp_url_origin($url) !== csp_url_origin(bp_self_origin())) {
        return null;
    }
    $p = parse_url($url);
    return bp_internal_base() . ($p['path'] ?? '/') . (isset($p['query']) ? '?' . $p['query'] : '');
}

/**
 * Send a real credentialed request to api.php with the learner's Origin.
 * An empty origin means "send no Origin header", which is what a same-origin
 * request looks like and is worth being able to compare against.
 */
function bp_cors_request(int $level, string $origin): array
{
    $headers = ['Cookie: ' . cors_session_cookie(), 'Accept: application/json'];
    if ($origin !== '') {
        array_unshift($headers, 'Origin: ' . $origin);
    }
    return bp_http(bp_internal_base() . '/api.php?level=' . $level, $headers);
}

/**
 * The last three trace stages every CORS level shares: the two headers that
 * were really returned, and what a browser does with them.
 */
function bp_cors_tail_stages(string $origin, array $res, array $verdict): array
{
    return [
        [
            'label'   => 'response header: Access-Control-Allow-Origin',
            'value'   => $verdict['acao'] === '' ? '(header absent)' : $verdict['acao'],
            'note'    => $verdict['acao'] === ''
                ? 'The policy did not match, so api.php emitted no CORS headers at all.'
                : 'Compare this with the Origin you sent. A browser only allows the read when they are identical.',
            'verdict' => $verdict['acao'] !== '' && $verdict['acao'] === $origin ? 'pass' : 'block',
        ],
        [
            'label'   => 'response header: Access-Control-Allow-Credentials',
            'value'   => $verdict['acac'] === '' ? '(header absent)' : $verdict['acac'],
            'note'    => 'Without this header the browser strips cookies from the request, and the API answers as a logged-out visitor.',
            'verdict' => strtolower($verdict['acac']) === 'true' ? 'pass' : null,
        ],
        [
            'label'   => 'what a browser does with this response',
            'value'   => $verdict['readable']
                ? ($verdict['credentialed'] ? 'script on ' . $origin . ' reads the authenticated response'
                                            : 'readable, but without cookies')
                : 'blocked: script cannot read the body',
            'note'    => $verdict['note'],
            'verdict' => $verdict['readable'] && $verdict['credentialed'] ? 'pass' : 'block',
        ],
    ];
}

/* =========================================================================
 * Shared UI
 * ===================================================================== */

function bp_extra_head(): string
{
    return '<style>
        .bp-hdr { font-family: "JetBrains Mono", ui-monospace, monospace; font-size: 0.74rem;
                  line-height: 1.7; white-space: pre-wrap; word-break: break-all; margin: 0; }
        .bp-hdr .bp-k { color: var(--text-muted); }
        .bp-hdr .bp-hit { color: var(--success); font-weight: 600; }
        .bp-hdr .bp-miss { color: var(--text-faint); }
        .bp-frame { width: 100%; height: 190px; border: 1px solid var(--border-mid);
                    border-radius: var(--radius); background: #c3c0b6; }
        .bp-live { margin-top: 0.5rem; }
        .bp-policy { font-family: "JetBrains Mono", ui-monospace, monospace; font-size: 0.74rem;
                     word-break: break-all; line-height: 1.7; }
        .bp-form { margin-bottom: 0.75rem; }
        .bp-actions { display: flex; gap: 0.6rem; flex-wrap: wrap; margin-top: 0.5rem; align-items: center; }
        textarea.form-control { font-family: "JetBrains Mono", ui-monospace, monospace;
                                font-size: 0.76rem; line-height: 1.6; }
    </style>';
}

/** The Origin input used by levels 1-5. */
function bp_origin_form(int $level, string $value, string $extra = ''): string
{
    ob_start(); ?>
    <form method="post" class="bp-form">
        <div class="form-group">
            <label class="form-label">Origin header your page would send</label>
            <input type="text" name="origin" class="form-control" spellcheck="false" autocomplete="off"
                   placeholder="https://attacker.test" value="<?= lk_esc($value) ?>">
        </div>
        <?= $extra ?>
        <div class="bp-actions">
            <button class="btn btn-primary" type="submit">Send request to /api.php?level=<?= $level ?></button>
            <a class="btn btn-outline" href="api.php?level=<?= $level ?>" target="_blank">Open the endpoint &rarr;</a>
        </div>
    </form>
    <?php
    return ob_get_clean();
}

/** The markup textarea used by the CSP levels. */
function bp_markup_form(string $value, string $label, string $placeholder, string $button = 'Render it'): string
{
    ob_start(); ?>
    <form method="post" class="bp-form">
        <div class="form-group">
            <label class="form-label"><?= lk_esc($label) ?></label>
            <textarea name="payload" class="form-control" rows="4" spellcheck="false"
                      placeholder="<?= lk_esc($placeholder) ?>"><?= lk_esc($value) ?></textarea>
        </div>
        <div class="bp-actions">
            <button class="btn btn-primary" type="submit"><?= lk_esc($button) ?></button>
        </div>
    </form>
    <?php
    return ob_get_clean();
}

/** Render the real response headers, highlighting the two that decide access. */
function bp_headers_box(array $raw, string $title = 'Real response headers'): string
{
    if (!$raw) {
        return '';
    }
    $out = '<div class="lk-box"><h4><span class="lk-tag">RESPONSE</span>' . lk_esc($title) . '</h4><div class="lk-body"><pre class="bp-hdr">';
    foreach ($raw as $line) {
        $pos = strpos($line, ':');
        if ($pos === false) {
            $out .= '<span class="bp-k">' . lk_esc($line) . '</span>' . "\n";
            continue;
        }
        $name = substr($line, 0, $pos);
        $rest = substr($line, $pos + 1);
        $hot  = in_array(strtolower(trim($name)), ['access-control-allow-origin', 'access-control-allow-credentials'], true);
        $out .= '<span class="' . ($hot ? 'bp-hit' : 'bp-k') . '">' . lk_esc($name) . ':</span>'
              . ($hot ? '<span class="bp-hit">' . lk_esc($rest) . '</span>' : lk_esc($rest)) . "\n";
    }
    if (!array_filter($raw, static fn($l) => stripos($l, 'access-control-allow-origin') === 0)) {
        $out .= '<span class="bp-miss">(no Access-Control-Allow-Origin in this response)</span>' . "\n";
    }
    return $out . '</pre></div></div>';
}

/** Show a response body the way the attacker page would have read it. */
function bp_body_box(string $body, string $title = 'Body the attacker script would read'): string
{
    if (trim($body) === '') {
        return '';
    }
    return '<div class="lk-box"><h4><span class="lk-tag lk-tag-red">DATA</span>' . lk_esc($title) . '</h4>'
         . '<div class="lk-body"><pre class="bp-hdr">' . lk_esc($body) . '</pre></div></div>';
}

/** The policy that was really sent, printed above the frame. */
function bp_policy_box(string $policy): string
{
    return '<div class="lk-box"><h4><span class="lk-tag">HEADER</span>Content-Security-Policy actually sent by render.php</h4>'
         . '<div class="lk-body"><div class="bp-policy">' . lk_esc($policy) . '</div></div></div>';
}

/**
 * The live frame. render.php sends the real CSP header, so whatever happens
 * inside this iframe is the browser's own verdict, not the lab's.
 */
function bp_frame(int $level, array $params, string $note = ''): string
{
    $qs  = http_build_query(array_merge(['level' => $level], $params));
    $url = 'render.php?' . $qs;
    ob_start(); ?>
    <div class="lk-box"><h4><span class="lk-tag">LIVE</span>The page, with that header, in your browser</h4>
        <div class="lk-body">
            <?php if ($note !== ''): ?><p class="lk-hintline"><?= $note ?></p><?php endif; ?>
            <iframe class="bp-frame" src="<?= lk_esc($url) ?>" title="render frame"></iframe>
            <div class="bp-actions">
                <a class="btn btn-outline" href="<?= lk_esc($url) ?>" target="_blank">Open the frame on its own &rarr;</a>
            </div>
            <div class="bp-live" id="bp-live"></div>
        </div>
    </div>
    <script>
    window.addEventListener('message', function (e) {
        if (!e.data || e.data.hlab !== 'win') return;
        var box = document.getElementById('bp-live');
        box.innerHTML = '<div class="message success">Your browser confirms it: script executed inside the frame ' +
                        'and called <code>hlab.win()</code>. The evaluation below reached the same conclusion ' +
                        'from the policy string.</div>';
    });
    </script>
    <?php
    return ob_get_clean();
}

/** Standard pass/fail block. */
function bp_verdict(bool $ok, string $html): string
{
    return '<div class="message ' . ($ok ? 'success' : 'error') . '">' . $html . '</div>';
}
