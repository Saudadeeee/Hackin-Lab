<?php
require_once __DIR__ . '/helpers.php';

$L    = 1;
$meta = gq_levels()[$L];

$query    = (string)($_POST['query'] ?? '');
$flag     = '';
$result   = '';
$stages   = [];

if (trim($query) !== '') {
    // ── The endpoint. Introspection was left enabled when the service shipped. ──
    $report = gql_execute(gq_schema_l1(), $query, [
        'introspection' => true,
        'suggestions'   => true,
    ]);
    $json   = gql_json($report['result']);
    $stages = gq_stages([[
        'label' => 'POST /graphql  (Content-Type: application/json)',
        'value' => json_encode(['query' => $query], JSON_UNESCAPED_SLASHES),
        'note'  => 'One HTTP request, one document. Everything below happens inside it.',
    ]], $report['trace'], [[
        'label'   => 'introspection flag on this endpoint',
        'value'   => 'introspection = true',
        'note'    => 'With this on, <code>__schema</code> and <code>__type</code> are ordinary fields on the query
                      root and the validator accepts them like any other.',
        'verdict' => 'pass',
    ]]);

    if (gql_data_contains($report['result'], gq_secret(1))) {
        $flag   = gq_flag($L);
        $result = '<div class="message success">The response body carries the embargo codeword.</div>';
    } elseif (isset($report['result']['errors'])) {
        $result = '<div class="message error">The endpoint returned errors. Read them: a GraphQL error is a
                   statement about the schema.</div>';
    } else {
        $result = '<div class="message info">Valid response, but no memo content in it yet.</div>';
    }
    $result .= gq_response_box($json);
}

$code = <<<'PHP'
// POST /graphql - the storefront's read API.
$body   = json_decode(file_get_contents('php://input'), true);
$report = gql_execute($schema, (string) $body['query'], [
    'introspection' => true,   // left on after the schema review "to help the front end"
    'suggestions'   => true,
]);

header('Content-Type: application/json');
echo json_encode($report['result']);

// ---- the schema this endpoint serves -------------------------------------
'Query' => ['fields' => [
    'me'           => ['type' => 'User'],
    'products'     => ['type' => '[Product]'],
    'product'      => ['type' => 'Product', 'args' => ['id' => ['type' => 'Int!']]],
    // Used by the internal comms tool. The storefront bundle never asks for it,
    // so nobody thought of it as part of the public surface.
    'internalMemo' => ['type' => 'Memo',    'args' => ['id' => ['type' => 'Int!']]],
]],
PHP;

$fixBad = <<<'PHP'
$report = gql_execute($schema, $body['query'], [
    'introspection' => true,
]);
PHP;

$fixGood = <<<'PHP'
// 1. Introspection is a development tool. Turn it off in production, or gate
//    it behind the same authentication as the rest of the admin surface.
$report = gql_execute($schema, $body['query'], [
    'introspection' => $env === 'local' || $viewer->isStaff(),
]);

// 2. More important: do not rely on that switch. A field the public endpoint
//    should not serve does not belong in the public endpoint's schema.
//    Build one schema per audience and let each one contain only what that
//    audience may read.
$schema = $viewer->isStaff() ? staff_schema() : public_schema();
PHP;

lk_page([
    'lab'        => gqlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => gq_extra_head(),
    'extra_body' => gq_editor_script(),

    'code'       => $code,
    'vuln_lines' => [4, 15, 16, 17],
    'annotation' => 'The endpoint answers <code>__schema</code>, so the whole type system is readable by anyone
        who can reach it. The schema also contains <code>internalMemo</code>, a field the front end never calls,
        which the team treated as private because no client referenced it.',

    'theory' => '<p>A REST service leaks its surface one guess at a time. A GraphQL service with introspection
        enabled hands the entire list over on request: every type, every field, every argument name and type,
        every mutation. Tooling depends on this. So does anyone probing the endpoint.</p>
        <p>The second half of the bug is the one that survives turning introspection off. Fields end up in a
        schema because some client needs them, and they stay there for every other client too. "The web app does
        not query it" is not access control; the schema is the API, and everything in the schema is callable.</p>
        <p>When you assess a GraphQL endpoint, read the schema for fields that no UI would ever want:
        <code>internal*</code>, <code>debug*</code>, <code>admin*</code>, anything returning a type whose name
        does not appear in the front-end bundle. Those fields tend to be the ones nobody wrote a resolver check
        for, because nobody expected them to be called.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Disabling introspection raises the cost of discovery. It does not remove the field, and the
            next level shows how much of the schema comes back without it.',
    ],

    'scenario' => '<strong>Scenario:</strong> a chandlery storefront serves its catalogue from
        <code>/graphql</code>. The bundle calls <code>me</code> and <code>products</code>, and nothing else.
        <br><strong>Goal:</strong> find a type and a field the UI never references, call it, and read the embargo
        codeword out of the response.',

    'model' => [
        'title' => 'How to read a schema you were not given',
        'html'  => '<p>Introspection is answered by ordinary fields on the query root, so you query them the way
        you query anything else.</p>
        <table class="lk-kv">
            <tr><td><code>__schema { types { name } }</code></td><td>every type name on the endpoint</td></tr>
            <tr><td><code>__schema { queryType { name } }</code></td><td>which type is the query root</td></tr>
            <tr><td><code>__type(name: "Query") { fields { name } }</code></td><td>the callable root fields</td></tr>
            <tr><td><code>fields { name args { name } }</code></td><td>what each field expects to be given</td></tr>
        </table>
        <p>Type references are wrapped: a field of type <code>[Memo]</code> reports <code>name: null</code> and
        <code>kind: "LIST"</code>, and the real name is one level down under <code>ofType</code>. That is why real
        introspection queries always ask for <code>ofType</code> a few levels deep.</p>',
    ],

    'form' => gq_identity('You are signed in as <code>guest</code> (user #2). Nothing on this level checks that;
        the lesson here is discovery, not authorisation.')
        . gq_editor([
            'action'   => 'level1.php',
            'query'    => $query !== '' ? $query : "{\n  products { id name price }\n}",
            'examples' => [
                ['label' => 'what the storefront bundle actually sends',
                 'query' => "{\n  me { username name }\n  products { id name price category }\n}"],
                ['label' => 'ask the server to describe itself',
                 'query' => "{\n  __schema {\n    queryType { name }\n    types { name kind }\n  }\n}"],
                ['label' => 'one type in detail, with argument names',
                 'query' => "{\n  __type(name: \"Query\") {\n    name\n    fields {\n      name\n      args { name type { name kind ofType { name } } }\n      type { name kind ofType { name } }\n    }\n  }\n}"],
            ],
        ]),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'A field with no client became a field with one client.',
    'why'      => '<p>The endpoint described itself, you read the description, and one of the root fields it
        listed had no counterpart anywhere in the front end. Calling it needed nothing beyond the argument name
        and type that introspection printed.</p>
        <p>Note what was <em>not</em> required: no credential, no guessing, no wordlist. The server volunteered
        the field name, its argument, and the shape of what it returns. Discovery on a GraphQL endpoint with
        introspection on is a single request.</p>',

    'pipeline' => $stages,
    'probes'   => [
        'param'  => 'query',
        'method' => 'POST',
        'action' => 'level1.php',
        'items'  => [
            ['q' => 'Does this endpoint answer introspection at all?',
             'payload' => '{ __schema { queryType { name } } }',
             'learn'   => 'One field, one request. If this comes back with data, everything else about the schema
                           is available to you. If it errors, the next level is the route.'],
            ['q' => 'Which root fields exist, and what does each one take?',
             'payload' => '{ __type(name: "Query") { fields { name args { name } } } }',
             'learn'   => 'Compare the list with what the page actually calls. The difference is your list of
                           candidates.'],
            ['q' => 'What does the undocumented field return?',
             'payload' => '{ __type(name: "Memo") { fields { name type { name } } } }',
             'learn'   => 'Knowing the field name is not enough - an object type needs a selection set. This tells
                           you which sub-fields are legal before you spend a request finding out.'],
        ],
    ],
    'hints' => gq_hints($L),
]);
