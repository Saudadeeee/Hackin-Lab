<?php
require_once __DIR__ . '/helpers.php';

$L    = 8;
$meta = gq_levels()[$L];

const L8_MAX_DEPTH = 3;

$query  = (string)($_POST['query'] ?? '');
$flag   = '';
$result = '';
$stages = [];

if (trim($query) !== '') {
    // The limiter lives inside the engine on this level (max_depth), and it
    // enforces the count taken on the operation AST, before expansion.
    $report = gql_execute(gq_schema_l8(), $query, [
        'introspection' => true,
        'suggestions'   => true,
        'max_depth'     => L8_MAX_DEPTH,
    ]);
    $json = gql_json($report['result']);

    $stages = gq_stages([[
        'label' => 'POST /graphql',
        'value' => json_encode(['query' => $query], JSON_UNESCAPED_SLASHES),
    ]], $report['trace'], [[
        'label'   => 'counter vs reality',
        'value'   => 'depth the limiter counted: ' . $report['depth']
                     . '    depth the executor actually walked: ' . $report['depth_expanded']
                     . '    limit: ' . L8_MAX_DEPTH,
        'note'    => $report['depth'] === $report['depth_expanded']
            ? 'No fragments in this document, so the two numbers agree and the limiter is accurate.'
            : 'The gap is the vulnerability. Every fragment spread hid one level plus everything under it from
               the count.',
        'verdict' => $report['depth_expanded'] > L8_MAX_DEPTH && $report['depth'] <= L8_MAX_DEPTH ? 'pass' : null,
    ]]);

    if (gql_data_contains($report['result'], gq_secret(8))) {
        $flag   = gq_flag($L);
        $result = '<div class="message success">The safe combination is in your response, from a query the
                   limiter measured as depth ' . (int)$report['depth'] . '.</div>';
    } elseif (isset($report['result']['errors'])) {
        $result = '<div class="message error">The endpoint returned errors.</div>';
    } else {
        $result = '<div class="message info">Executed, but the response does not reach the safe yet.</div>';
    }
    $result .= gq_response_box($json);
}

$code = <<<'PHP'
// Depth limiting, run on the parsed document before execution.
function depth(array $selections): int
{
    $max = 0;
    foreach ($selections as $s) {
        if ($s['kind'] === 'field') {
            $d = 1 + ($s['selections'] ? depth($s['selections']) : 0);
        } else {
            // A fragment spread has no selection set of its own here, so it
            // is a leaf as far as this function is concerned.
            $d = 1;
        }
        $max = max($max, $d);
    }
    return $max;
}

if (depth($operation['selections']) > 3) {
    return response(['errors' => [['message' => 'Query is too deep.']]], 400);
}

// Execution, further down, resolves fragment spreads into the fields they
// stand for and walks as deep as those fields go.
$data = execute($schema, $operation, $fragments);
PHP;

$fixBad = <<<'PHP'
} else {
    $d = 1;                       // fragment spread: counted as a leaf
}
PHP;

$fixGood = <<<'PHP'
} elseif ($s['kind'] === 'spread') {
    // Measure what execution will do: descend into the fragment, tracking
    // the spreads already on the stack so a cyclic document terminates.
    if (isset($visited[$s['name']])) {
        throw new GqlError('Fragment cycle: ' . $s['name']);
    }
    $visited[$s['name']] = true;
    $d = depth($fragments[$s['name']]['selections'], $fragments, $visited);
}

// Depth alone is a weak budget in any case. Cost the query: fields resolved,
// list sizes multiplied down the tree, and a per-field weight for the
// expensive resolvers. Reject on cost, and keep depth as a cheap early bail.
PHP;

lk_page([
    'lab'        => gqlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => gq_extra_head(),
    'extra_body' => gq_editor_script(),

    'code'       => $code,
    'vuln_lines' => [10, 11, 12, 13],
    'annotation' => 'The counter walks the operation AST and treats a fragment spread as a leaf, because at that
        point a spread genuinely has no children. Fragments are resolved later, by the executor, which then walks
        the full nesting. The number that is enforced and the number that happens are different numbers.',

    'theory' => '<p>Static analysis of a query is only as good as its model of execution. A depth limiter is a
        model: it claims that walking the operation AST tells you how deep the executor will go. Fragments break
        that claim, because a fragment definition sits outside the operation and is stitched in at execution
        time.</p>
        <p>The mitigation this defeats is usually deployed against denial of service - deeply nested queries over
        recursive types can multiply into an enormous amount of work. But depth limits are also used as a
        <em>reachability</em> control, on the reasoning that sensitive data is far from the root and a shallow
        query cannot get there. That reasoning fails here twice: fragments recover the depth, and distance from
        the root was never an access control in the first place.</p>
        <p>The general lesson: whenever two components read the same input and only one of them is the
        enforcement point, look for an input where they disagree. Level 7 was a guard reading one array element;
        this is an analyser reading a document without the definitions that complete it. Both are parser
        differentials, and both are found by asking "what does the enforcing component <em>not</em> model?".</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Expanding fragments in the counter needs a cycle guard, because a document may define
            <code>fragment A on T { ...B }</code> and <code>fragment B on T { ...A }</code>. A recursive counter
            with no guard turns that into a stack overflow, which is a denial of service in the code meant to
            prevent one.',
    ],

    'scenario' => '<strong>Scenario:</strong> the HR graph exposes an org chart. <code>Employee.manager</code>
        returns another <code>Employee</code>, so the type is recursive, and a depth limit of
        <strong>' . L8_MAX_DEPTH . '</strong> was added to stop clients walking it forever. The executive safe
        hangs off the record four hops above you.
        <br><strong>Goal:</strong> read <code>combination</code> from a document the limiter accepts.',

    'model' => [
        'title' => 'Two ways to write the same query',
        'html'  => '<p>The direct form, and what the counter sees:</p>
        <pre class="lk-sinkline">{ me { manager { manager { safe { combination } } } } }
   1      2         3       4        5          -> depth 5, rejected</pre>
        <p>The same traversal, with the tail moved into fragments:</p>
        <pre class="lk-sinkline">{ me { manager { ...A } } }              -> counted:  1, 2, 3 (spread is a leaf)
fragment A on Employee { manager { ...B } }
fragment B on Employee { safe { combination } }   -> executed: 5</pre>
        <table class="lk-kv">
            <tr><td><code>fragment Name on Type { … }</code></td><td>a named selection set, defined at the top
                level of the document</td></tr>
            <tr><td><code>...Name</code></td><td>spread it here; the type condition must match the type you are
                currently on</td></tr>
            <tr><td><code>... on Type { … }</code></td><td>inline fragment, no definition needed</td></tr>
        </table>
        <p>The org chart is <code>Guest Analyst &rarr; Priya Raman &rarr; Ken Osei</code>, and
        <code>Ken Osei</code> is a keyholder.</p>',
    ],

    'form' => gq_identity('Depth limit on this endpoint: <strong>' . L8_MAX_DEPTH . '</strong>. The trace prints
        both the counted depth and the real one for every document you send.')
        . gq_editor([
            'action'   => 'level8.php',
            'query'    => $query !== '' ? $query : "{\n  me { id name title }\n}",
            'examples' => [
                ['label' => 'shallow, accepted',
                 'query' => "{\n  me { name title manager { name title } }\n}"],
                ['label' => 'the direct route to the safe, rejected',
                 'query' => "{\n  me { manager { manager { safe { label combination } } } }\n}"],
                ['label' => 'a fragment, to see how the counter treats a spread',
                 'query' => "{\n  me { manager { ...M } }\n}\n\nfragment M on Employee {\n  name\n  title\n}"],
            ],
        ]),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'Counted at ' . L8_MAX_DEPTH . ', executed at 5.',
    'why'      => '<p>Your operation body was three levels deep and the counter stopped at the spread, so the
        limiter passed the document. The executor then substituted each fragment for the fields it defines and
        kept resolving, two levels further than the limiter believed possible, all the way to
        <code>Safe.combination</code>.</p>
        <p>Nothing was smuggled and nothing was malformed - this is an ordinary, specification-compliant document
        that a client generator might well produce on its own. The limiter measured a different thing from
        the one it was protecting.</p>',

    'pipeline' => $stages,
    'probes'   => [
        'param'  => 'query',
        'method' => 'POST',
        'action' => 'level8.php',
        'items'  => [
            ['q' => 'Where exactly does the limit bite?',
             'payload' => '{ me { manager { manager { name } } } }',
             'learn'   => 'Four levels. Compare the counted depth in the trace with the limit and you know the
                           budget you have to work inside.'],
            ['q' => 'Does the counter charge anything for a fragment spread?',
             'payload' => '{ me { manager { ...M } } } fragment M on Employee { name title }',
             'learn'   => 'Same shape as the previous probe but with the last level behind a spread. If the
                           counted depth drops, the spread is being treated as a leaf.'],
            ['q' => 'Do fragments actually expand, or are they silently dropped?',
             'payload' => '{ me { ...M } } fragment M on Employee { name title manager { name } }',
             'learn'   => 'The response has to contain the manager for the technique to be worth anything.
                           Confirm the executor really does follow the definition.'],
        ],
    ],
    'hints' => gq_hints($L),
]);
