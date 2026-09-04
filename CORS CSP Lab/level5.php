<?php
require_once __DIR__ . '/helpers.php';

$L    = 5;
$meta = bp_levels()[$L];

$legacyHost = 'legacy.hackinlab.internal';

$submitted = isset($_POST['origin']);
$origin    = bp_single_line((string)($_POST['origin'] ?? ''));
$note      = (string)($_POST['note'] ?? '');
$flag      = '';
$result    = '';
$pipeline  = [];
$boxes     = '';

/**
 * Did the legacy page really turn $note into an executable script node?
 * The answer comes from parsing the page's own HTML output, not from looking
 * at the payload: fetch the page, find the element the note is printed into,
 * and ask whether that subtree contains a script the browser would run.
 */
function level5_legacy_effect(string $host, string $note): array
{
    $url = 'http://' . $host . '/legacy.php?note=' . rawurlencode($note);
    $res = bp_http($url);
    if (!$res['ok']) {
        return ['ok' => false, 'url' => $url, 'body' => '', 'detail' => $res['error'], 'nodes' => []];
    }

    $prev = libxml_use_internal_errors(true);
    $doc  = new DOMDocument();
    $doc->loadHTML($res['body'], LIBXML_NONET);
    libxml_clear_errors();
    libxml_use_internal_errors($prev);

    $xp    = new DOMXPath($doc);
    $nodes = [];
    foreach ($xp->query('//*[@id="note"]//script') as $s) {
        /** @var DOMElement $s */
        $src  = $s->getAttribute('src');
        $text = trim($s->textContent);
        if ($src === '' && $text === '') {
            continue;                       // an empty tag runs nothing
        }
        $nodes[] = $src !== '' ? '<script src="' . $src . '">' : '<script> with ' . strlen($text) . ' bytes of code';
    }
    foreach ($xp->query('//*[@id="note"]//*') as $el) {
        /** @var DOMElement $el */
        foreach ($el->attributes ?? [] as $attr) {
            if (str_starts_with(strtolower($attr->nodeName), 'on') && $attr->nodeValue !== '') {
                $nodes[] = '<' . strtolower($el->nodeName) . ' ' . strtolower($attr->nodeName) . '="...">';
            }
        }
    }

    return [
        'ok'     => $nodes !== [],
        'url'    => $url,
        'body'   => $res['body'],
        'detail' => $nodes !== []
            ? 'The document returned by legacy.php contains ' . count($nodes) . ' executable node(s) inside #note.'
            : 'The note was reflected, but nothing inside #note is a node the browser would execute.',
        'nodes'  => $nodes,
    ];
}

if ($submitted) {
    $res     = bp_cors_request($L, $origin);
    $verdict = cors_browser_verdict($origin, $res['map']);

    $parts   = parse_url($origin);
    $scheme  = is_array($parts) ? ($parts['scheme'] ?? '') : '';
    $host    = is_array($parts) ? strtolower($parts['host'] ?? '') : '';
    $inside  = in_array($scheme, ['http', 'https'], true) && cors_is_internal_host($host);

    $effect  = $note !== '' ? level5_legacy_effect($legacyHost, $note)
                            : ['ok' => false, 'url' => '', 'body' => '', 'detail' => 'No note submitted.', 'nodes' => []];

    $pipeline = array_merge([
        [
            'label'   => 'wildcard check: host === domain || str_ends_with($host, \'.\' . $domain)',
            'value'   => ($host === '' ? '(unparseable)' : $host) . ' => ' . ($inside ? 'inside the wildcard' : 'outside'),
            'note'    => 'This check is written correctly. It parses the origin and requires a real subdomain '
                       . 'boundary, so there is no string trick to find in it.',
            'verdict' => $inside ? 'pass' : 'block',
        ],
    ], bp_cors_tail_stages($origin, $res, $verdict), [
        [
            'label'   => 'GET http://' . $legacyHost . '/legacy.php?note=...',
            'value'   => $effect['url'] === '' ? '(not requested)' : $effect['url'],
            'note'    => 'A second, real request &mdash; to a host the wildcard already trusts.',
        ],
        [
            'label'   => 'HTML parse of the returned page, subtree #note',
            'value'   => $effect['nodes'] ? implode(' , ', $effect['nodes']) : 'no executable nodes',
            'note'    => $effect['detail'] . ' The verdict comes from a DOM parse of the response, so a payload that '
                       . 'does not survive the page&rsquo;s markup counts as a failure here.',
            'verdict' => $effect['ok'] ? 'pass' : 'block',
        ],
    ]);

    $boxes = bp_headers_box($res['raw'])
           . ($verdict['readable'] && $verdict['credentialed'] ? bp_body_box($res['body']) : '')
           . ($effect['body'] !== '' ? bp_body_box($effect['body'], 'What legacy.php actually returned') : '');

    if ($verdict['readable'] && $verdict['credentialed'] && $inside && $effect['ok']) {
        $flag   = bp_flag($L);
        $result = bp_verdict(true,
            'Both halves landed. <code>' . lk_esc($origin) . '</code> holds a credentialed grant from the API, and '
            . '<code>' . lk_esc($legacyHost) . '</code> executes script you supplied. Script running there can read '
            . 'the account response with the victim&rsquo;s cookies.');
    } elseif ($verdict['readable'] && $verdict['credentialed'] && $inside) {
        $result = bp_verdict(false,
            'The origin is trusted, so half of the chain is in place. You still need code running <em>on</em> that '
            . 'origin: the note has to come back as a node the browser executes.');
    } elseif ($effect['ok']) {
        $result = bp_verdict(false,
            'The legacy page executes your markup, but the origin you sent does not hold a credentialed grant. '
            . 'Send the origin of the host you took over.');
    } elseif ($origin === '' && $note === '') {
        $result = bp_verdict(false, 'Nothing submitted. Both fields matter here.');
    } else {
        $result = bp_verdict(false, $verdict['note']);
    }
}

$code = <<<'PHP'
// GET /api.php?level=5
// "Any of our own hosts may call the API. The security review asked for
//  a real subdomain check this time."
const DOMAIN = 'hackinlab.internal';

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$parts  = parse_url($origin);
$scheme = $parts['scheme'] ?? '';
$host   = $parts['host']   ?? '';

$ok = in_array($scheme, ['http', 'https'], true)
    && ($host === DOMAIN || str_ends_with($host, '.' . DOMAIN));

if ($ok) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
    header('Vary: Origin');
}

// ---------------------------------------------------------------------
// legacy.hackinlab.internal / legacy.php - retired 2019, still routed,
// no CSP, and inside the wildcard above.
// ---------------------------------------------------------------------
$note = $_GET['note'] ?? '';
echo '<div id="note">' . $note . '</div>';
PHP;

$fixBad = <<<'PHP'
$ok = $host === DOMAIN || str_ends_with($host, '.' . DOMAIN);
if ($ok) { allow($origin); }   // every host under the domain, forever
PHP;

$fixGood = <<<'PHP'
// 1. Name the origins that actually call this API. A wildcard is a
//    standing grant to hosts that do not exist yet.
const ALLOWED = [
    'https://portal.hackinlab.internal',
    'https://admin.hackinlab.internal',
];
if (in_array($origin, ALLOWED, true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
}
header('Vary: Origin');

// 2. And on the legacy host, escape the reflection. Both fixes are
//    needed: either one alone leaves the chain one bug from working.
echo '<div id="note">' . htmlspecialchars($note, ENT_QUOTES, 'UTF-8') . '</div>';
PHP;

lk_page([
    'lab'        => bp_lab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => bp_extra_head(),

    'code'       => $code,
    'vuln_lines' => [11, 12, 25],
    'annotation' => 'The origin check is correct. The vulnerability is the size of the set it approves: every host
        under <code>hackinlab.internal</code>, including a retired status page that prints a query parameter into
        the document with no escaping.',

    'theory' => '<p>A <code>*.domain</code> CORS allowlist is a statement about hosts that do not exist yet. It says
        that any current or future name under the domain may read authenticated API responses. That makes the API&rsquo;s
        security equal to the security of the <em>weakest</em> host in the domain, and nobody maintains an inventory
        of those.</p>
        <p>The weak link does not have to be dramatic. Cross-site scripting on any allowlisted host is enough,
        because script running there has that host&rsquo;s origin, and the API grants that origin a credentialed
        read. Subdomain takeover works the same way: a dangling DNS record pointing at a deprovisioned bucket or
        platform gives an attacker a host inside the wildcard without touching the company&rsquo;s systems at all.</p>
        <p>This is why the interesting question about an allowlist is not "is the matching correct" but "what is the
        full set of things that can satisfy it, and who controls each one". The chain here has two links and each
        one is individually defensible: a wildcard for internal hosts is normal, and an unescaped parameter on a
        retired status board is a low-severity finding on its own. Chained, they hand out an API key.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Fix both ends. Enumerating origins removes the standing grant to hosts nobody owns any more;
            escaping the reflection removes the weak link. If a wildcard is genuinely unavoidable, treat every host
            inside it as part of the API&rsquo;s trust boundary: inventory them, scan them, and remove the DNS
            records of hosts that no longer exist.',
    ],

    'scenario' => '<strong>Scenario:</strong> the origin check was rewritten properly and now allows any host under
        <code>hackinlab.internal</code>. One of those hosts is
        <a href="legacy.php?note=hello" target="_blank">legacy.php</a> on <code>' . $legacyHost . '</code>, a status
        board retired in 2019 that still resolves.
        <br><strong>Goal:</strong> read the authenticated account response from an origin the wildcard trusts, using
        code you put there yourself.',

    'model' => [
        'title' => 'The chain, one link at a time',
        'html'  => '<table class="lk-kv">
            <tr><td>1</td><td>Find a host inside <code>*.hackinlab.internal</code> that you can run script on.</td></tr>
            <tr><td>2</td><td><code>' . $legacyHost . '</code> prints <code>?note=</code> into the page unescaped.</td></tr>
            <tr><td>3</td><td>Script running there has origin <code>http://' . $legacyHost . '</code>.</td></tr>
            <tr><td>4</td><td>The API grants that origin a credentialed read, so the script fetches the account data
                with the victim&rsquo;s cookies and sends it wherever it likes.</td></tr>
        </table>
        <p>The two boxes below drive both halves for real: the Origin box sends a genuine request to
        <code>api.php</code>, and the note box sends a genuine request to <code>legacy.php</code>. The flag needs a
        credentialed grant <em>and</em> a script node that a DOM parse of the legacy page can find.</p>',
    ],

    'form' => bp_origin_form($L, $origin,
        '<div class="form-group">'
        . '<label class="form-label">note parameter for http://' . $legacyHost . '/legacy.php</label>'
        . '<textarea name="note" class="form-control" rows="3" spellcheck="false" '
        . 'placeholder="what the retired status board should print">' . lk_esc($note) . '</textarea>'
        . '</div>'),

    'result'   => $result . $boxes,
    'flag'     => $flag,
    'flag_msg' => 'The allowlist was correct and the host inside it was not.',
    'why'      => '<p>Nothing in the origin check was defeated. The trace shows it approving your origin because the
        origin genuinely is a subdomain of <code>hackinlab.internal</code> &mdash; which it is, because you took
        over a host that was already inside the wildcard.</p>
        <p>The last trace stage is the part that matters: a DOM parse of the page <code>legacy.php</code> really
        returned found a script node built from your parameter. That is what gives you an execution context on the
        trusted origin, and everything else follows from the API&rsquo;s own policy.</p>
        <p>Generalise the shape rather than the payload. Whenever a security decision is made about a <em>set</em> of
        principals &mdash; a wildcard origin, a wildcard certificate, a group membership, an IP range &mdash; the
        decision inherits the weakest member of the set. Enumerate the set before you accept the check.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'origin',
        'method' => 'POST',
        'action' => 'level5.php',
        'items'  => [
            ['q'       => 'Did the level-4 payload get fixed?',
             'payload' => 'https://evilhackinlab.internal',
             'learn'   => 'A refusal proves the host is now parsed and the dot is required, so the string tricks from '
                        . 'levels 3 and 4 are both closed and the target has to be a host you take over.'],
            ['q'       => 'Which internal hosts does the wildcard accept?',
             'payload' => 'http://legacy.hackinlab.internal',
             'learn'   => 'Confirms the retired status board is inside the trust boundary, and that plain http is '
                        . 'accepted. Half the chain, with no payload involved.'],
            ['q'       => 'Is the API reachable from a host with a similar name?',
             'payload' => 'http://legacy.hackinlab.internal.evil.test',
             'learn'   => 'A refusal is the useful answer: it tells you the only way into the wildcard is a host that '
                        . 'genuinely sits under the domain.'],
        ],
    ],
    'hints' => bp_hints($L),
]);
