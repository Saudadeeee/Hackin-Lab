<?php
require_once __DIR__ . '/helpers.php';

$L    = 2;
$meta = bp_levels()[$L];

$allowlist = [
    'https://portal.hackinlab.internal',
    'https://admin.hackinlab.internal',
    'null',
];

$submitted = isset($_POST['origin']);
$origin    = bp_single_line((string)($_POST['origin'] ?? ''));
$flag      = '';
$result    = '';
$pipeline  = [];
$boxes     = '';

if ($submitted) {
    $res     = bp_cors_request($L, $origin);
    $verdict = cors_browser_verdict($origin, $res['map']);
    $matched = in_array($origin, $allowlist, true);

    $pipeline = array_merge([
        [
            'label' => 'request header: Origin',
            'value' => $origin === '' ? '(no Origin header sent)' : $origin,
        ],
        [
            'label'   => 'in_array($origin, $allowlist, true)',
            'value'   => $matched ? 'true' : 'false',
            'note'    => 'The comparison itself is strict and correct. The allowlist is '
                       . '<code>' . lk_esc(implode(', ', $allowlist)) . '</code>.',
            'verdict' => $matched ? 'pass' : 'block',
        ],
    ], bp_cors_tail_stages($origin, $res, $verdict));

    $boxes = bp_headers_box($res['raw'])
           . ($verdict['readable'] && $verdict['credentialed'] ? bp_body_box($res['body']) : '');

    if ($verdict['readable'] && $verdict['credentialed'] && $verdict['acao'] === 'null') {
        $flag   = bp_flag($L);
        $result = bp_verdict(true,
            'The API returned <code>Access-Control-Allow-Origin: null</code> together with credentials. '
            . 'Any document in an opaque origin now reads this response, and an attacker can put a document '
            . 'in an opaque origin whenever they like.');
    } elseif ($verdict['readable'] && $verdict['credentialed']) {
        $result = bp_verdict(false,
            'Granted &mdash; but <code>' . lk_esc($origin) . '</code> is one of the two real company origins, which '
            . 'is the allowlist working as intended. Look at the entry that is not an origin at all.');
    } elseif ($origin === '') {
        $result = bp_verdict(false, 'No Origin header was sent, so the allowlist was never consulted.');
    } else {
        $result = bp_verdict(false, $verdict['note']);
    }
}

$code = <<<'PHP'
// GET /api.php?level=2
$allowlist = [
    'https://portal.hackinlab.internal',
    'https://admin.hackinlab.internal',
    // Added during the mobile release: "the webview and the sandboxed
    // preview send Origin: null and the API kept rejecting them"
    'null',
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if (in_array($origin, $allowlist, true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
    header('Vary: Origin');
}
PHP;

$fixBad = <<<'PHP'
$allowlist = ['https://portal.hackinlab.internal', 'null'];
if (in_array($origin, $allowlist, true)) { allow($origin); }
PHP;

$fixGood = <<<'PHP'
// "null" is not an origin you can authorise; it is the absence of one.
// Remove it, and give the sandboxed surface a real origin of its own.
$allowlist = [
    'https://portal.hackinlab.internal',
    'https://admin.hackinlab.internal',
    'https://preview.hackinlab.internal',   // the preview got its own host
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== 'null' && in_array($origin, $allowlist, true)) {
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
    'vuln_lines' => [7],
    'annotation' => 'The allowlist and the comparison are both correct. The defect is a value: <code>null</code> is
        what a browser sends when the requesting document has no origin it can name, and any page on the internet
        can produce such a document on demand.',

    'theory' => '<p>Every document has an origin, but some documents have an <em>opaque</em> one &mdash; a unique
        value that is not equal to itself and cannot be written down. The serialisation of an opaque origin is the
        four characters <code>null</code>, and that is what arrives in the <code>Origin</code> header.</p>
        <p>Documents get an opaque origin in ordinary, attacker-reachable ways: an
        <code>&lt;iframe sandbox="allow-scripts"&gt;</code> without <code>allow-same-origin</code>, a
        <code>data:</code> URL, a page loaded from the local filesystem, and in some browsers a document arrived at
        through a cross-origin redirect. None of those require any privilege. An attacker page embeds a
        sandboxed iframe and runs script inside it.</p>
        <p>So <code>null</code> in an allowlist does not mean "our sandboxed preview". It means "any document that
        has been stripped of its identity", which is a set the attacker can join at will. The entry usually gets
        added while debugging, because the log shows <code>Origin: null</code> being rejected and adding it makes
        the error stop.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The right response to "our sandboxed surface sends <code>Origin: null</code>" is to stop
            sandboxing away the identity you need, or to give that surface a real origin. If a caller genuinely
            cannot present an origin, it should authenticate with a token rather than being granted a credentialed
            read on the strength of a header it did not have to earn.',
    ],

    'scenario' => '<strong>Scenario:</strong> the API now has a real allowlist. During the mobile release someone
        added a third entry so the sandboxed preview would stop failing.
        <br><strong>Goal:</strong> get a credentialed grant without controlling either of the two company origins.',

    'model' => [
        'title' => 'Where Origin: null comes from',
        'html'  => '<table class="lk-kv">
            <tr><td><code>&lt;iframe sandbox="allow-scripts"&gt;</code></td><td>opaque origin, script still runs.
                The standard way an attacker produces this on their own page.</td></tr>
            <tr><td><code>data:</code> URL document</td><td>opaque origin.</td></tr>
            <tr><td><code>file://</code> document</td><td>opaque origin in current browsers.</td></tr>
            <tr><td>some cross-origin redirects</td><td>the origin is downgraded to <code>null</code> in transit.</td></tr>
        </table>
        <p>The attacker&rsquo;s page:</p>
        <div class="source-code"><pre><code>&lt;iframe sandbox="allow-scripts" srcdoc="&lt;script&gt;
  fetch(\'https://api.hackinlab.internal/api.php?level=2\', { credentials: \'include\' })
    .then(r =&gt; r.text()).then(d =&gt; parent.postMessage(d, \'*\'));
&lt;/script&gt;"&gt;&lt;/iframe&gt;</code></pre></div>
        <p>Requests from that iframe carry <code>Origin: null</code>. Type the same value in the box below and the
        lab will send it for you.</p>',
    ],

    'form'     => bp_origin_form($L, $origin),
    'result'   => $result . $boxes,
    'flag'     => $flag,
    'flag_msg' => 'An allowlist entry that names no one let everyone in.',
    'why'      => '<p>Stage 2 shows the strict comparison returning true, because the string you sent is literally
        in the array. There is no bypass here in the usual sense &mdash; the code did what it was told, and what it
        was told was wrong.</p>
        <p>The reason this is worth its own level is that it survives every review that asks "is the origin
        compared correctly?". The comparison is fine. What needs reviewing is the <em>contents</em> of the list, and
        the question to ask about each entry is: who can cause a browser to send this?</p>
        <p>For <code>null</code>, the answer is anybody with a web page.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'origin',
        'method' => 'POST',
        'action' => 'level2.php',
        'items'  => [
            ['q'       => 'Is this a real allowlist, or reflection again?',
             'payload' => 'https://attacker.test',
             'learn'   => 'The level-1 payload. A refusal here tells you the comparison is real and that you have to '
                        . 'attack the contents of the list rather than the test.'],
            ['q'       => 'What does an approved origin look like when it succeeds?',
             'payload' => 'https://admin.hackinlab.internal',
             'learn'   => 'A grant you were always going to get. Useful as a reference for the header shape, and it '
                        . 'confirms which entries are live.'],
            ['q'       => 'Is the match case-sensitive and exact?',
             'payload' => 'HTTPS://Portal.HackinLab.Internal',
             'learn'   => 'A refusal proves <code>in_array(..., true)</code> is comparing raw bytes. That rules out '
                        . 'casing tricks and points you at the one entry that is not an origin.'],
        ],
    ],
    'hints' => bp_hints($L),
]);
