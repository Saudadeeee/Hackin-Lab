<?php
require_once __DIR__ . '/helpers.php';

$L    = 4;
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
    $matched = $origin !== '' && str_ends_with($origin, 'hackinlab.internal');

    $host     = cors_origin_host($origin);
    $internal = $host !== '' && cors_is_internal_host($host);

    $pipeline = array_merge([
        [
            'label' => 'request header: Origin',
            'value' => $origin === '' ? '(no Origin header sent)' : $origin,
        ],
        [
            'label' => 'the last 18 characters of the origin',
            'value' => $origin === '' ? '' : substr($origin, -18),
            'note'  => 'This is the entire subject of the test. The scheme, the separator and every label to the '
                     . 'left of it are outside the comparison.',
        ],
        [
            'label'   => 'str_ends_with($origin, \'hackinlab.internal\')',
            'value'   => $matched ? 'true' : 'false',
            'verdict' => $matched ? 'pass' : 'block',
        ],
        [
            'label'   => 'parse_url($origin, PHP_URL_HOST)   // the host a browser derives',
            'value'   => $host === '' ? '(not a parseable origin)' : $host,
            'note'    => $internal
                ? 'A genuine host inside hackinlab.internal.'
                : 'The suffix test passed, and yet this host is not under hackinlab.internal &mdash; there is no dot '
                . 'in front of the matched text.',
            'verdict' => $matched && !$internal && $host !== '' ? 'pass' : null,
        ],
    ], bp_cors_tail_stages($origin, $res, $verdict));

    $boxes = bp_headers_box($res['raw'])
           . ($verdict['readable'] && $verdict['credentialed'] ? bp_body_box($res['body']) : '');

    if ($verdict['readable'] && $verdict['credentialed'] && $host !== '' && !$internal) {
        $flag   = bp_flag($L);
        $result = bp_verdict(true,
            'Credentialed read granted to <code>' . lk_esc($origin) . '</code>. The host is '
            . '<code>' . lk_esc($host) . '</code>, a registrable domain of its own that merely ends in the same '
            . 'eighteen characters.');
    } elseif ($verdict['readable'] && $verdict['credentialed']) {
        $result = bp_verdict(false,
            '<code>' . lk_esc($host) . '</code> really is inside hackinlab.internal, so this grant is the intended '
            . 'behaviour. Keep the suffix and change what sits immediately before it.');
    } elseif ($origin === '') {
        $result = bp_verdict(false, 'No Origin header was sent, so the suffix test was never reached.');
    } else {
        $result = bp_verdict(false, $verdict['note']);
    }
}

$code = <<<'PHP'
// GET /api.php?level=4
// Review comment on the previous version: "the regex was unanchored,
// use a suffix test instead". This is what shipped.
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if ($origin !== '' && str_ends_with($origin, 'hackinlab.internal')) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
    header('Vary: Origin');
}
PHP;

$fixBad = <<<'PHP'
if (str_ends_with($origin, 'hackinlab.internal')) { allow($origin); }
PHP;

$fixGood = <<<'PHP'
// Parse the origin, then decide about the host as a hostname:
// either it IS the domain, or it is a label plus a dot plus the domain.
const DOMAIN = 'hackinlab.internal';

$parts  = parse_url($origin);
$scheme = $parts['scheme'] ?? '';
$host   = strtolower($parts['host'] ?? '');

$ok = $scheme === 'https'
    && !isset($parts['port'], $parts['path'])
    && ($host === DOMAIN || str_ends_with($host, '.' . DOMAIN));

if ($ok) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
}
header('Vary: Origin');
PHP;

lk_page([
    'lab'        => bp_lab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => bp_extra_head(),

    'code'       => $code,
    'vuln_lines' => [6],
    'annotation' => 'The suffix test runs against the whole origin string, scheme included, and never requires a
        <code>.</code> immediately before the domain. Any longer label that happens to end in those characters
        passes, and that label belongs to whoever registered it.',

    'theory' => '<p>Level 3 anchored the start and forgot the end; this one anchors the end and forgets the start.
        Together they are the same lesson from both directions: an origin check has to constrain the <em>whole</em>
        value, and it has to know where the host boundaries are.</p>
        <p>The boundary between hostname labels is a literal dot. <code>evilhackinlab.internal</code> and
        <code>evil.hackinlab.internal</code> differ by one character and by everything that matters: the first is a
        second-level domain anyone can register under <code>.internal</code>, the second is a subdomain only the
        domain owner can create. A test that does not require the dot cannot tell them apart.</p>
        <p>The same shape appears far outside CORS. Redirect allowlists (<code>str_contains($url, "example.com")</code>),
        SSRF filters that check the host ends with an internal suffix, email-domain checks that accept
        <code>@notgmail.com</code>, and cookie-domain logic all fail in exactly this way. Whenever you see a
        hostname compared with a substring operation, ask what character is guarding the boundary.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Two things make the patched version correct: it compares the parsed <em>host</em> rather than the
            serialised origin, and it spells the subdomain case as <code>&#39;.&#39; . DOMAIN</code> so the separator
            is part of the comparison. The explicit <code>$host === DOMAIN</code> branch is there because
            <code>.hackinlab.internal</code> is not a suffix of <code>hackinlab.internal</code>.',
    ],

    'scenario' => '<strong>Scenario:</strong> the unanchored regex from level 3 was flagged in review and replaced
        with a suffix test, which looked stricter.
        <br><strong>Goal:</strong> get a credentialed grant for a domain you could register, using the new check.',

    'model' => [
        'title' => 'Where the boundary went missing',
        'html'  => '<table class="lk-kv">
            <tr><td><code>https://evil.hackinlab.internal</code></td><td>a real subdomain &mdash; only the domain
                owner can create it</td></tr>
            <tr><td><code>https://evilhackinlab.internal</code></td><td>a different registrable domain &mdash; ends
                with the same 18 characters, no dot</td></tr>
            <tr><td><code>https://xhackinlab.internal</code></td><td>likewise</td></tr>
        </table>
        <p><code>str_ends_with</code> cannot distinguish the first row from the other two, because the character it
        would have to look at is the one it never reads. Contrast this with level 3, where the missing anchor was at
        the other end of the string:</p>
        <div class="source-code"><pre><code>level 3   ^https?://portal.hackinlab.internal        ...anything
level 4              anything...        hackinlab.internal$
correct   parse it, then host === D || endsWith(host, "." + D)</code></pre></div>',
    ],

    'form'     => bp_origin_form($L, $origin),
    'result'   => $result . $boxes,
    'flag'     => $flag,
    'flag_msg' => 'A missing dot is the whole difference between a subdomain and a stranger.',
    'why'      => '<p>Stage 2 isolates what the check actually looked at: the final eighteen characters. Stage 4
        shows the hostname a browser derives from the same string. Your origin satisfied the first and failed to be
        anything the company owns, which is precisely the state the test cannot detect.</p>
        <p>Both of the last two levels were written by someone trying to be careful. Anchoring one end feels like
        tightening the check, and the review comment that produced this code was itself correct as far as it went.
        The class of bug survives because the fix is aimed at the symptom instead of at the decision to compare
        strings at all.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'origin',
        'method' => 'POST',
        'action' => 'level4.php',
        'items'  => [
            ['q'       => 'Did the previous level&rsquo;s payload get fixed?',
             'payload' => 'https://portal.hackinlab.internal.evil.test',
             'learn'   => 'A refusal confirms the end is now anchored, so the suffix trick from level 3 is closed and '
                        . 'you should look at the other end of the string.'],
            ['q'       => 'Is a genuine subdomain accepted?',
             'payload' => 'https://reports.hackinlab.internal',
             'learn'   => 'Establishes the intended behaviour. The check is supposed to admit subdomains, which tells '
                        . 'you what it must be doing with the dot &mdash; or not doing.'],
            ['q'       => 'Does the scheme have to be https?',
             'payload' => 'http://reports.hackinlab.internal',
             'learn'   => 'The suffix test never looks at the scheme, so plaintext origins pass too. Worth noting '
                        . 'before you decide what your final origin should look like.'],
        ],
    ],
    'hints' => bp_hints($L),
]);
