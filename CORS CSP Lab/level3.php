<?php
require_once __DIR__ . '/helpers.php';

$L    = 3;
$meta = bp_levels()[$L];

$submitted = isset($_POST['origin']);
$origin    = bp_single_line((string)($_POST['origin'] ?? ''));
$flag      = '';
$result    = '';
$pipeline  = [];
$boxes     = '';

if ($submitted) {
    $res     = bp_cors_request($L, $origin);
    $verdict = cors_browser_verdict($origin, $res['map']);

    // The same expression api.php evaluated, re-run here purely to display it.
    $matched = $origin !== '' && preg_match('~^https?://portal\.hackinlab\.internal~', $origin) === 1;

    $host     = cors_origin_host($origin);
    $isPortal = $host === 'portal.hackinlab.internal';

    $pipeline = array_merge([
        [
            'label' => 'request header: Origin',
            'value' => $origin === '' ? '(no Origin header sent)' : $origin,
        ],
        [
            'label'   => 'preg_match(\'~^https?://portal\.hackinlab\.internal~\', $origin)',
            'value'   => $matched ? '1' : '0',
            'note'    => '<code>^</code> pins the start of the subject. Nothing pins the end, so the pattern is '
                       . 'asking &ldquo;does this origin <em>begin with</em> the trusted one&rdquo;.',
            'verdict' => $matched ? 'pass' : 'block',
        ],
        [
            'label'   => 'parse_url($origin, PHP_URL_HOST)   // what the browser will actually treat as the host',
            'value'   => $host === '' ? '(not a parseable origin)' : $host,
            'note'    => $isPortal
                ? 'This is the genuine portal host.'
                : 'The regex approved this origin. The host it really names is the one printed here.',
            'verdict' => $matched && !$isPortal && $host !== '' ? 'pass' : null,
        ],
    ], bp_cors_tail_stages($origin, $res, $verdict));

    $boxes = bp_headers_box($res['raw'])
           . ($verdict['readable'] && $verdict['credentialed'] ? bp_body_box($res['body']) : '');

    if ($verdict['readable'] && $verdict['credentialed'] && $host !== '' && !cors_is_internal_host($host)) {
        $flag   = bp_flag($L);
        $result = bp_verdict(true,
            'The API granted a credentialed read to <code>' . lk_esc($origin) . '</code>. Its registrable domain is '
            . '<code>' . lk_esc($host) . '</code>, which has nothing to do with hackinlab.internal.');
    } elseif ($verdict['readable'] && $verdict['credentialed']) {
        $result = bp_verdict(false,
            'Granted, but <code>' . lk_esc($host) . '</code> is still inside hackinlab.internal. The regex is doing '
            . 'its job for this input; make it approve a host that is yours.');
    } elseif ($origin === '') {
        $result = bp_verdict(false, 'No Origin header was sent, so <code>preg_match</code> was never reached.');
    } else {
        $result = bp_verdict(false, $verdict['note']);
    }
}

$code = <<<'PHP'
// GET /api.php?level=3
// "The allowlist got long once every environment had its own portal
//  hostname, so we matched a pattern instead."
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if ($origin !== '' && preg_match('~^https?://portal\.hackinlab\.internal~', $origin)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
    header('Vary: Origin');
}
PHP;

$fixBad = <<<'PHP'
if (preg_match('~^https?://portal\.hackinlab\.internal~', $origin)) {
    allow($origin);
}
PHP;

$fixGood = <<<'PHP'
// Parse first, then compare the parts. A host is not a substring of a
// string, it is a field of a URL, and it has to match exactly.
$parts = parse_url($origin);
$ok = is_array($parts)
    && ($parts['scheme'] ?? '') === 'https'
    && ($parts['host']   ?? '') === 'portal.hackinlab.internal'
    && !isset($parts['port'], $parts['path'], $parts['query']);

if ($ok) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
}
header('Vary: Origin');

// If a pattern really is unavoidable, anchor both ends and escape the
// dots:  ~^https://[a-z0-9-]+\.hackinlab\.internal$~
PHP;

lk_page([
    'lab'        => bp_lab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => bp_extra_head(),

    'code'       => $code,
    'vuln_lines' => [6],
    'annotation' => 'The pattern is anchored at the start with <code>^</code> and nowhere else, so it matches any
        origin that <em>begins with</em> the trusted one. Everything after the trusted prefix is free, including
        more hostname.',

    'theory' => '<p>Hostnames are hierarchical from right to left. In <code>a.b.example.com</code> the owner of
        <code>example.com</code> controls everything to the left, and nobody else does. Humans read left to right,
        which is why <code>portal.hackinlab.internal.evil.test</code> looks like the portal at a glance and is
        actually a name inside <code>evil.test</code>.</p>
        <p>An unanchored pattern turns that reading order against the reviewer. The check appears to say
        "the origin is the portal" and actually says "the origin starts with these characters". Registering a domain
        that starts with somebody else&rsquo;s full origin costs a few dollars.</p>
        <p>The general rule is that an origin is a parsed structure &mdash; scheme, host, port &mdash; and a
        security decision about it must compare those fields, not the text they were serialised from. Every time a
        comparison is done on the serialisation instead, there is an attacker-controlled part of the string that the
        comparison forgot to constrain. Level 4 is the same mistake pointing the other way.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Note the extra checks on port and path in the patched version. An origin has no path, so an input
            that has one is not an origin and should be refused rather than partially matched. If you must use a
            regular expression, anchor it with <code>^</code> <em>and</em> <code>$</code>, and escape every dot &mdash;
            an unescaped <code>.</code> matches any character, which is a second way the same check leaks.',
    ],

    'scenario' => '<strong>Scenario:</strong> staging, QA and production each have their own portal hostname, so the
        allowlist was replaced with a pattern.
        <br><strong>Goal:</strong> get a credentialed grant for a host inside a domain you could register today.',

    'model' => [
        'title' => 'What the pattern actually constrains',
        'html'  => '<table class="lk-kv">
            <tr><td><code>^</code></td><td>the match must start at the beginning of the origin</td></tr>
            <tr><td><code>https?://</code></td><td>either scheme</td></tr>
            <tr><td><code>portal\\.hackinlab\\.internal</code></td><td>these literal characters</td></tr>
            <tr><td><em>(nothing)</em></td><td>&hellip; and then anything at all, for any length</td></tr>
        </table>
        <p>So the origins below all match. Only the first one is the portal.</p>
        <div class="source-code"><pre><code>https://portal.hackinlab.internal          the real one
https://portal.hackinlab.internal.evil.test   host is evil.test
https://portal.hackinlab.internalXYZ.test     host is internalXYZ.test
http://portal.hackinlab.internal.attacker.io  plain http, still matches</code></pre></div>',
    ],

    'form'     => bp_origin_form($L, $origin),
    'result'   => $result . $boxes,
    'flag'     => $flag,
    'why'      => '<p>Stage 2 shows <code>preg_match</code> returning 1 for your origin, and stage 3 shows the host
        a browser derives from that same string. They disagree, and the gap between them is the vulnerability: the
        check reasoned about characters while the browser reasoned about a hostname.</p>
        <p>The response then echoed your full origin back in <code>Access-Control-Allow-Origin</code>, which means
        the browser hands the authenticated body to script running on a domain you control.</p>
        <p>Reviewing for this is quick: find every regular expression used on a URL or origin and check that it ends
        in <code>$</code>. Then check that every <code>.</code> is escaped.</p>',
    'flag_msg' => 'A pattern that pinned one end approved a domain at the other.',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'origin',
        'method' => 'POST',
        'action' => 'level3.php',
        'items'  => [
            ['q'       => 'Is the check anchored at the start?',
             'payload' => 'https://notportal.hackinlab.internal',
             'learn'   => 'A refusal proves <code>^</code> is present and that prefixing does not work. Half the '
                        . 'question is now answered; the other half is the end of the string.'],
            ['q'       => 'Is any suffix accepted at all?',
             'payload' => 'https://portal.hackinlab.internalX',
             'learn'   => 'One extra character, still inside no real domain. If this is approved, the pattern has no '
                        . 'end anchor and the shape of the exploit follows immediately.'],
            ['q'       => 'Does it insist on https?',
             'payload' => 'http://portal.hackinlab.internal',
             'learn'   => '<code>https?</code> makes the s optional. Worth knowing separately: an allowlisted plaintext '
                        . 'origin can also be taken over by anyone on the network path.'],
        ],
    ],
    'hints' => bp_hints($L),
]);
