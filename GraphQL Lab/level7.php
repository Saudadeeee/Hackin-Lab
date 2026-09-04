<?php
require_once __DIR__ . '/helpers.php';

$L    = 7;
$meta = gq_levels()[$L];

/** Root fields the service considers administrative. */
$PROTECTED_FIELDS = ['auditLog', 'exportUsers'];

$sessionUser = 2;
$sessionRole = (string)(gq_user($sessionUser)['role'] ?? 'user');

$body   = (string)($_POST['query'] ?? '');
$flag   = '';
$result = '';
$stages = [];

if (trim($body) !== '') {
    $decoded = json_decode($body, true);

    if (!is_array($decoded)) {
        $result = '<div class="message error">The request body has to be JSON: either one
                   <code>{"query": "…"}</code> object or an array of them.</div>';
        $stages = [['label' => 'json_decode($rawBody)', 'value' => $body,
                    'note' => 'Decode failed: ' . lk_esc(json_last_error_msg()), 'verdict' => 'block']];
    } else {
        // A single object is treated as a batch of one, which is how most
        // batching servers normalise the two shapes.
        $ops     = array_keys($decoded) === range(0, count($decoded) - 1) ? $decoded : [$decoded];
        $isBatch = count($ops) > 1;

        // ── The guard. It reads element zero. ──────────────────────────────
        $firstQuery = (string)($ops[0]['query'] ?? '');
        $hit        = null;
        foreach ($PROTECTED_FIELDS as $f) {
            if (preg_match('/\b' . preg_quote($f, '/') . '\b/', $firstQuery)) {
                $hit = $f;
            }
        }
        $blocked = $hit !== null && $sessionRole !== 'admin';

        $stages[] = [
            'label' => 'raw request body',
            'value' => $body,
            'note'  => 'Decoded into ' . count($ops) . ' operation(s). Every one of them will be executed.',
        ];
        $stages[] = [
            'label'   => 'guard: scan($body[0]["query"], $PROTECTED_FIELDS)',
            'value'   => 'inspected element 0 only:  ' . ($firstQuery === '' ? '(empty)' : $firstQuery)
                         . "\nmatch: " . ($hit ?? 'none') . '   your role: ' . $sessionRole,
            'note'    => $blocked
                ? 'Element 0 mentions a protected field and you are not an admin, so nothing runs.'
                : 'Element 0 is clean, so the request is allowed. Elements 1 and up were not read by this
                   function - it only ever indexes <code>[0]</code>.',
            'verdict' => $blocked ? 'block' : 'pass',
        ];

        if ($blocked) {
            $result = '<div class="message error">403 Forbidden &mdash; <code>' . lk_esc($hit)
                    . '</code> requires the admin role.</div>'
                    . gq_response_box(gql_json(['errors' => [['message' =>
                        'Field "' . $hit . '" requires role "admin".']]]));
        } else {
            $trace    = new GqlTrace();
            $envelope = [];
            $hitFlag  = false;

            foreach ($ops as $i => $op) {
                $trace->add('executing batch element [' . $i . ']', (string)($op['query'] ?? ''),
                    $i === 0 ? 'The one element the guard looked at.'
                             : 'Never seen by the guard. The executor treats it exactly like element 0.');
                $report     = gql_execute(gq_schema_l7(), (string)($op['query'] ?? ''), [
                    'introspection' => true,
                    'suggestions'   => true,
                    'operationName' => $op['operationName'] ?? null,
                    'trace'         => $trace,
                ]);
                $envelope[] = $report['result'];
                if (gql_data_contains($report['result'], gq_secret(7))) {
                    $hitFlag = true;
                }
            }

            $json   = gql_json($envelope);
            $stages = gq_stages($stages, $trace);

            if ($hitFlag) {
                $flag   = gq_flag($L);
                $result = '<div class="message success">The audit trail came back in one of the envelopes.</div>';
            } else {
                $result = '<div class="message info">' . count($ops) . ' operation(s) executed, nothing
                           privileged in the response.</div>';
            }
            $result .= gq_response_box($json, 'Raw JSON response (one envelope per operation)');
        }
    }
}

$code = <<<'PHP'
// The endpoint accepts either one operation or an array of them, and the
// client library batches aggressively to save round trips.
$body = json_decode($rawBody, true);
$ops  = array_is_list($body) ? $body : [$body];

// Field-level access control, applied to the incoming request.
$PROTECTED_FIELDS = ['auditLog', 'exportUsers'];

foreach ($PROTECTED_FIELDS as $field) {
    if (preg_match('/\b' . $field . '\b/', $body[0]['query'])   // <- element zero
        && $session->role !== 'admin') {
        return response(['errors' => [['message' => 'Forbidden']]], 403);
    }
}

// Everything in the array is executed and the envelopes are returned in order.
$out = [];
foreach ($ops as $op) {
    $out[] = gql_execute($schema, $op['query'], [
        'operationName' => $op['operationName'] ?? null,
    ])['result'];
}
echo json_encode($out);
PHP;

$fixBad = <<<'PHP'
foreach ($PROTECTED_FIELDS as $field) {
    if (preg_match('/\b' . $field . '\b/', $body[0]['query'])
        && $session->role !== 'admin') {
        return forbidden();
    }
}
PHP;

$fixGood = <<<'PHP'
// 1. Whatever the control is, apply it to every element - or refuse the batch.
foreach ($ops as $i => $op) {
    $policy->check($op, $session, "batch[$i]");
}

// 2. Better: stop policing request text and put the decision in the resolver,
//    where it runs once per execution regardless of how the request was framed.
'auditLog' => [
    'type'    => '[AuditEntry]',
    'resolve' => function ($r, $a, $ctx) {
        $ctx['viewer']->require('audit.read');
        return $repo->auditEntries();
    },
],

// 3. And cap the batch. An unbounded array is also an amplification primitive.
if (count($ops) > 10) {
    return response(['errors' => [['message' => 'Batch too large.']]], 400);
}
PHP;

lk_page([
    'lab'        => gqlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => gq_extra_head(),
    'extra_body' => gq_editor_script(),

    'code'       => $code,
    'vuln_lines' => [10, 11, 12, 13, 14],
    'annotation' => 'The endpoint executes every element of the array. The guard indexes
        <code>$body[0]</code> and loops over the field list rather than over the operations, so exactly one of
        them is ever inspected.',

    'theory' => '<p>Batching is a transport convenience: several operations, one HTTP request, one array of
        envelopes back. It is supported by most GraphQL clients and enabled by default in several servers.
        The moment it is on, "the request" stops being a single thing, and every control written against
        "the request" has to be re-read as "which part of the request".</p>
        <p>An index-zero guard is easy to write by accident. Someone normalises the body into <code>$ops</code>
        for the executor, then writes the security check against <code>$body</code> because that is what the
        original single-operation code did. Both work in every test, because tests send one operation.</p>
        <p>This is the same family as level 5: a control counted or applied per request, and a request that can
        carry arbitrarily much. Related shapes worth checking on real targets - HTTP parameter pollution where a
        WAF reads the first <code>?id=</code> and the app reads the last, JSON bodies with duplicate keys, and
        multipart requests where one parser stops at the first part.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Fix 1 is the minimum. Fix 2 is what makes the class of bug go away: a check inside the
            resolver does not care whether the operation arrived alone, in position 7, or under an alias.',
    ],

    'scenario' => '<strong>Scenario:</strong> the storefront client batches its calls. The administrative
        <code>auditLog</code> field is guarded by a request filter.
        <br><strong>Goal:</strong> you are <code>guest</code>, role <code>' . lk_esc($sessionRole) . '</code>.
        Read the audit trail and recover the payroll export key.',

    'model' => [
        'title' => 'The batch body, and where the guard looks',
        'html'  => '<pre class="lk-sinkline">[ {"query": "{ me { username } }"},        <-- element 0, inspected
  {"query": "{ auditLog { entry } }"} ]     <-- element 1, executed</pre>
        <p>The response mirrors the request: an array of <code>{"data":…}</code> envelopes in the same order, so
        the answer to element 1 is the second item.</p>
        <p>The editor below sends the box contents as the raw request body, so type valid JSON. Every element
        needs a <code>query</code> key; <code>operationName</code> and <code>variables</code> are optional per
        element.</p>',
    ],

    'form' => gq_identity('You are <code>guest</code>, role <code>' . lk_esc($sessionRole) . '</code>. The box
        below is the raw HTTP body, not a GraphQL document.')
        . gq_editor([
            'action' => 'level7.php',
            'label'  => 'POST /graphql &mdash; raw JSON request body',
            'button' => 'Send request body',
            'rows'   => 7,
            'query'  => $body !== '' ? $body : '[{"query": "{ me { username role } }"}]',
            'examples' => [
                ['label' => 'a single operation, the ordinary shape',
                 'query' => '{"query": "{ me { username role } }"}'],
                ['label' => 'a batch of two harmless operations',
                 'query' => '[{"query": "{ me { username } }"},' . "\n" . ' {"query": "{ products { id name } }"}]'],
                ['label' => 'the protected field, in element 0',
                 'query' => '[{"query": "{ auditLog { actor entry } }"}]'],
            ],
        ]),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'Element zero was clean, and element one was never read by the guard.',
    'why'      => '<p>The guard ran its regular expression over <code>$body[0]["query"]</code>, found nothing
        administrative, and returned. The executor then iterated the whole array. Your second element asked for
        <code>auditLog</code>, its resolver has no authorisation code of its own, and the rows came back in the
        second envelope.</p>
        <p>The trace makes the asymmetry explicit: one element inspected, two elements executed. Any number of
        operations can hide behind a compliant first entry.</p>',

    'pipeline' => $stages,
    'probes'   => [
        'param'  => 'query',
        'method' => 'POST',
        'action' => 'level7.php',
        'items'  => [
            ['q' => 'Does the endpoint accept an array body at all?',
             'payload' => '[{"query": "{ me { username } }"}, {"query": "{ products { id } }"}]',
             'learn'   => 'Two envelopes in the response means batching is on. If you get one envelope or an
                           error, this level would have to be attacked some other way.'],
            ['q' => 'Is the protected field blocked when it is the only operation?',
             'payload' => '[{"query": "{ auditLog { id } }"}]',
             'learn'   => 'Confirms the guard exists and that it fires on the field name. Now you know what it
                           is looking for and, from the code, where it looks.'],
            ['q' => 'Which elements does the guard actually read?',
             'payload' => '[{"query": "{ me { username } }"}, {"query": "{ products { id name } }"}, {"query": "{ me { role } }"}]',
             'learn'   => 'All three are harmless. Compare the trace with the previous probe: the guard prints
                           exactly one inspected element regardless of how many you send.'],
        ],
    ],
    'hints' => gq_hints($L),
]);
