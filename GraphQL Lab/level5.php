<?php
require_once __DIR__ . '/helpers.php';

$L    = 5;
$meta = gq_levels()[$L];

if (!empty($_POST['_reset'])) {
    gq_reset_state();                                // clears the rate-limit window
    header('Location: level5.php');
    exit;
}

$ip     = (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
$query  = (string)($_POST['query'] ?? '');
$flag   = '';
$result = '';
$stages = [];

if (trim($query) !== '') {
    // ── The limiter. It runs once per HTTP request, before the document is
    //    parsed, and it counts requests. ────────────────────────────────────
    $rate = gq_rate_check($ip, $L, 5, 60);

    $stages[] = [
        'label'   => 'rate limiter (per client, per minute)',
        'value'   => $rate['used'] . ' / ' . $rate['limit'] . ' requests in the last '
                     . $rate['window'] . ' seconds',
        'note'    => 'Counted before the body is parsed. At this point the server does not yet know how many
                      operations the request contains.',
        'verdict' => $rate['allowed'] ? 'pass' : 'block',
    ];

    if (!$rate['allowed']) {
        $result = '<div class="message error">429 Too Many Requests &mdash; five requests per minute per client.
                   Wait for the window to roll over, or press <em>Reset lab state</em>.</div>'
                . gq_response_box(gql_json(['errors' => [['message' => 'Rate limit exceeded. Try again later.']]]));
    } else {
        $report = gql_execute(gq_schema_l5(), $query, ['introspection' => true, 'suggestions' => true]);
        $json   = gql_json($report['result']);

        // Top-level resolver paths have no dot in them: one per aliased call.
        $ops = count(array_filter($report['resolvers'], static fn($p) => strpos($p, '.') === false));

        $stages = gq_stages($stages, $report['trace'], [[
            'label'   => 'operations performed by this single request',
            'value'   => $ops . ' call(s) to Query.redeem, complexity ' . $report['complexity'],
            'note'    => 'The limiter charged you <strong>1</strong> for all of them. Requests per minute and
                          operations per minute are not the same quantity.',
            'verdict' => $ops > 1 ? 'pass' : null,
        ]]);

        if (gql_data_contains($report['result'], gq_secret(5))) {
            $flag   = gq_flag($L);
            $result = '<div class="message success">One of the aliased calls matched, and the voucher reward is
                       in the response.</div>';
        } elseif (isset($report['result']['errors'])) {
            $result = '<div class="message error">The endpoint returned errors.</div>';
        } else {
            $result = '<div class="message info">' . $ops . ' code(s) tried in this request, none of them
                       matched.</div>';
        }
        $result .= gq_response_box($json);
    }
}

$code = <<<'PHP'
// Rate limiting middleware, applied to POST /graphql
$hits = $store->countSince($clientIp, now() - 60);
if ($hits >= 5) {
    return response(['errors' => [['message' => 'Rate limit exceeded.']]], 429);
}
$store->record($clientIp, now());          // one row per HTTP request

// ... and only now is the body parsed and executed
$report = gql_execute($schema, (string) $body['query'], []);

// ---- the field being protected -------------------------------------------
'redeem' => [
    'type' => 'RedeemResult',
    'args' => ['code' => ['type' => 'String!']],
    'resolve' => function ($root, $args) {
        $row = $repo->coupon(strtoupper($args['code']));   // 2 chars, [0-9A-F]
        return ['code' => $args['code'], 'ok' => (bool) $row,
                'reward' => $row['reward'] ?? null];
    },
],
PHP;

$fixBad = <<<'PHP'
$hits = $store->countSince($clientIp, now() - 60);
if ($hits >= 5) { return too_many_requests(); }
$store->record($clientIp, now());
PHP;

$fixGood = <<<'PHP'
// Charge for the work the document asks for, not for the envelope it arrived
// in. Parse first, cost the operation, then decide.
$doc  = parse($body['query']);
$cost = complexity($doc);                  // fields resolved, list sizes, depth

if (!$budget->consume($clientIp, $cost)) {
    return response(['errors' => [['message' => 'Query cost budget exceeded.']]], 429);
}

// Sensitive fields get their own counter, keyed on the field and the actor,
// so 256 aliased calls to redeem() are 256 attempts however they arrived.
$attempts->charge($clientIp, 'redeem', count_field_calls($doc, 'redeem'));
PHP;

$aliasBuilder = <<<'JS'
<script>
document.addEventListener("click", function (e) {
    if (e.target.id !== "gq-build-aliases") return;
    var hex = "0123456789ABCDEF", lines = [];
    for (var i = 0; i < 16; i++) {
        for (var j = 0; j < 16; j++) {
            var c = hex[i] + hex[j];
            lines.push('  a' + c + ': redeem(code: "' + c + '") { code ok reward }');
        }
    }
    var ed = document.getElementById("gq-editor");
    ed.value = "{\n" + lines.join("\n") + "\n}";
    ed.focus();
});
</script>
JS;

lk_page([
    'lab'        => gqlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => gq_extra_head(),
    'extra_body' => gq_editor_script() . $aliasBuilder,

    'code'       => $code,
    'vuln_lines' => [2, 3, 4, 5, 6],
    'annotation' => 'The limiter counts HTTP requests. It runs before the document is parsed, so at the moment it
        makes its decision it cannot know whether the request contains one call to <code>redeem</code> or two
        hundred and fifty six. Aliases let one request carry as many as you like.',

    'theory' => '<p>An alias renames a field in the response: <code>a: redeem(code:"00")</code> and
        <code>b: redeem(code:"01")</code> are two independent calls with two independent arguments and two keys in
        the result. Aliases exist because a client may legitimately need the same field twice with different
        arguments. They also mean the ratio of <em>work</em> to <em>requests</em> is entirely under the client\'s
        control.</p>
        <p>Any control counted per request inherits that problem: rate limits, brute-force lockouts, "three
        attempts then a captcha", audit log entries, per-request billing. If the counter increments in
        middleware and the work happens in resolvers, the two numbers drift apart the moment a client sends more
        than one operation.</p>
        <p>The same reasoning applies to batching (level 7) and to lists: a field returning a hundred items whose
        resolver runs one query per item is a hundred queries for one increment. This is why mature GraphQL
        deployments cost queries by complexity rather than by count, and why sensitive operations carry their own
        attempt counter keyed on the actor rather than on the connection.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Note the second half of the fix. A global cost budget stops resource exhaustion; it does not
            stop a credential brute force, because 256 cheap calls may well fit inside a generous budget. The
            sensitive operation needs its own counter.',
    ],

    'scenario' => '<strong>Scenario:</strong> launch vouchers are two characters long, drawn from
        <code>0-9A-F</code>, so there are 256 of them. The endpoint allows five requests per minute per client.
        <br><strong>Goal:</strong> find the valid code and read its reward without waiting out the limiter.',

    'model' => [
        'title' => 'Requests, operations, and what each control counts',
        'html'  => '<table class="lk-kv">
            <tr><td>one request, one call</td><td>256 requests needed &rarr; 52 minutes at 5/min</td></tr>
            <tr><td>one request, 256 aliases</td><td>1 request, 256 resolver calls, one increment</td></tr>
        </table>
        <p>The alias syntax is <code>&lt;alias&gt;: &lt;field&gt;(&lt;args&gt;) { … }</code>. An alias must be a
        valid GraphQL name, so it cannot start with a digit - <code>a00:</code> works, <code>00:</code> does
        not.</p>
        <p>The response keys back the aliases, so you can read the winning entry directly:
        <code>{"data":{"a00":{"ok":false,…},"a01":{"ok":false,…}, …}}</code>. Searching the response for
        <code>"ok":true</code> is faster than reading it.</p>',
    ],

    'form' => gq_identity('Limit: five POSTs per minute per client address. The <em>Reset lab state</em> button
        clears the window if you lock yourself out.')
        . gq_editor([
            'action'   => 'level5.php',
            'reset'    => true,
            'query'    => $query !== '' ? $query : "{\n  redeem(code: \"00\") { code ok reward }\n}",
            'extra_controls' => '<p class="gq-note"><button type="button" class="btn btn-outline"
                 id="gq-build-aliases">Build all 256 aliases</button> &mdash; writes the full document into the
                 editor so you can read it before sending it.</p>',
            'examples' => [
                ['label' => 'one code per request (the slow way)',
                 'query' => "{\n  redeem(code: \"00\") { code ok reward }\n}"],
                ['label' => 'three codes in one request, using aliases',
                 'query' => "{\n  a: redeem(code: \"00\") { code ok }\n  b: redeem(code: \"01\") { code ok }\n  c: redeem(code: \"02\") { code ok }\n}"],
            ],
        ]),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'Two hundred and fifty six attempts, one increment on the counter.',
    'why'      => '<p>The limiter recorded a single row for the request and let it through. The parser then found
        256 field selections, and the executor called <code>Query.redeem</code> once for each, with the argument
        each alias supplied. One of those arguments matched the coupon row, and its resolver returned the
        reward.</p>
        <p>Nothing about the limiter is broken in isolation - it does exactly what it says. It is measuring the
        wrong unit, and GraphQL makes the gap between that unit and the actual work unbounded.</p>',

    'pipeline' => $stages,
    'probes'   => [
        'param'  => 'query',
        'method' => 'POST',
        'action' => 'level5.php',
        'items'  => [
            ['q' => 'What does a wrong code look like in the response?',
             'payload' => '{ redeem(code: "00") { code ok reward } }',
             'learn'   => 'Establish the shape of a miss so you can recognise a hit. One request spent.'],
            ['q' => 'Does the server accept the same field twice in one document?',
             'payload' => '{ a: redeem(code: "01") { code ok } b: redeem(code: "02") { code ok } }',
             'learn'   => 'Two keys in the response means aliases are supported and each call carried its own
                           argument. That is the whole technique, at a scale you can read.'],
            ['q' => 'Does the limiter charge per operation or per request?',
             'payload' => '{ a: redeem(code: "03") { ok } b: redeem(code: "04") { ok } c: redeem(code: "05") { ok } }',
             'learn'   => 'Watch the counter in the trace across these three probes. If it moves by one each
                           time regardless of how many aliases you sent, you have your answer.'],
        ],
    ],
    'hints' => gq_hints($L),
]);
