<?php
require_once __DIR__ . '/helpers.php';

$L    = 4;
$meta = gq_levels()[$L];

$sessionUser = 2;
$query       = (string)($_POST['query'] ?? '');
$flag        = '';
$result      = '';
$stages      = [];

if (trim($query) !== '') {
    $report = gql_execute(gq_schema_l4($sessionUser), $query, [
        'introspection' => true,
        'suggestions'   => true,
        'context'       => ['session_user_id' => $sessionUser],
    ]);
    $json   = gql_json($report['result']);
    $stages = gq_stages([[
        'label' => 'session established by the cookie',
        'value' => 'session_user_id = ' . $sessionUser,
        'verdict' => 'pass',
    ], [
        'label' => 'POST /graphql',
        'value' => json_encode(['query' => $query], JSON_UNESCAPED_SLASHES),
    ]], $report['trace']);

    if (gql_data_contains($report['result'], gq_secret(4))) {
        $flag   = gq_flag($L);
        $result = '<div class="message success">The administrator\'s live API token is in your response.</div>';
    } elseif (isset($report['result']['errors'])) {
        $result = '<div class="message error">Some fields refused. Note that the others still returned:
                   a field error nulls one field and leaves the rest of the response intact.</div>';
    } else {
        $result = '<div class="message info">Valid response, nothing privileged in it yet.</div>';
    }
    $result .= gq_response_box($json);
}

$code = <<<'PHP'
// Level 3 is fixed: the object-level decision is made once, in Query.user,
// and stamped on the row for the field resolvers to honour.
'user' => [
    'args'    => ['id' => ['type' => 'Int!']],
    'resolve' => function ($root, $args, $ctx) {
        $row = $repo->find((int) $args['id']);
        $row['_authorised'] = ((int) $args['id'] === $ctx['session_user_id']);
        return $row;
    },
],

// Written with the check, in the same sprint:
'email'       => ['resolve' => fn ($u) => $u['_authorised'] ? $u['email']        : deny('email')],
'ssn'         => ['resolve' => fn ($u) => $u['_authorised'] ? $u['ssn']          : deny('ssn')],
'privateNote' => ['resolve' => fn ($u) => $u['_authorised'] ? $u['private_note'] : deny('privateNote')],

// Added six months later for the mobile app. Re-fetches by id, on its own.
'apiToken' => [
    'type'    => 'String',
    'resolve' => fn ($u) => $db->query(
        'SELECT api_token FROM users WHERE id = ' . (int) $u['id']
    )->fetchColumn(),
],
PHP;

$fixBad = <<<'PHP'
$row['_authorised'] = ((int) $args['id'] === $ctx['session_user_id']);
// ... and every field resolver is trusted to look at it
'apiToken' => ['resolve' => fn ($u) => $db->fetchToken((int) $u['id'])],
PHP;

$fixGood = <<<'PHP'
// Make the unchecked read impossible to express. The resolver receives a
// value object that only exists if the policy allowed it, so a new field
// added in a hurry has nothing unauthorised to reach for.
'resolve' => function ($root, $args, $ctx) {
    return $policy->viewableUser($ctx['viewer'], (int) $args['id']);
    // -> ViewableUser, whose ->apiToken() throws unless the policy said yes
},

// Or declare the requirement next to the field, so it cannot be forgotten:
'apiToken' => [
    'type'    => 'String',
    'auth'    => 'self',            // enforced by the field middleware
    'resolve' => fn ($u) => $u->apiToken(),
],
PHP;

lk_page([
    'lab'        => gqlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => gq_extra_head(),
    'extra_body' => gq_editor_script(),

    'code'       => $code,
    'vuln_lines' => [18, 19, 20, 21, 22],
    'annotation' => 'The object-level decision from level 3 is now correct, and three field resolvers honour it.
        The fourth resolver fetches its value from the database by id and never reads
        <code>_authorised</code>, so selecting that field alone skips the check entirely.',

    'theory' => '<p>GraphQL resolves field by field. A selection set is not one authorisation event, it is one
        event per field, and the engine happily returns a partial response where some fields are populated and
        others carry an error. That is a feature - and it means a single unguarded field resolver is a complete
        bypass of everything its siblings do.</p>
        <p>The pattern that produces this bug is ordinary: a decision is computed in one place and left on the
        object as a flag, and honouring the flag is a convention rather than a mechanism. Conventions survive
        exactly as long as the people who know about them. The resolver that broke this one was written for a
        different client, six months later, and did its own database read because that was simpler.</p>
        <p>When testing, do not select a whole type at once. Select fields one at a time and compare: the field
        that answers where its neighbours refuse is the one with its own code path. When building, prefer designs
        where an unauthorised read cannot be written down - a value object that never holds the sensitive value,
        or field middleware that reads a declared requirement from the schema.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Either fix works. The common property is that authorisation stops being something a resolver
            has to remember to do and becomes something it cannot avoid.',
    ],

    'scenario' => '<strong>Scenario:</strong> the IDOR from level 3 was reported and fixed.
        <code>Query.user</code> now compares the requested id with the session and marks the row accordingly.
        <br><strong>Goal:</strong> you are user #2. Read the administrator\'s API token anyway.',

    'model' => [
        'title' => 'Reading a partial response',
        'html'  => '<p>Select three fields on a foreign account and the envelope looks like this:</p>
        <pre class="lk-sinkline">{"data":{"user":{"name":"Dana Root","ssn":null,"email":null}},
 "errors":[{"message":"Not authorised …","path":["user","ssn"]},
           {"message":"Not authorised …","path":["user","email"]}]}</pre>
        <p>Three facts in one response: <code>name</code> has no check, <code>ssn</code> and <code>email</code>
        do, and the <code>path</code> array tells you exactly which resolver refused. Enumerating a type this way
        costs one request per batch of fields, and the errors map the guard for you.</p>
        <p>Use introspection to get the field list first, then take them a few at a time.</p>',
    ],

    'form' => gq_identity('You are user <strong>#2</strong>. User #1 is <code>root</code>, the administrator.')
        . gq_editor([
            'action'   => 'level4.php',
            'query'    => $query !== '' ? $query : "{\n  user(id: 1) { name ssn email }\n}",
            'examples' => [
                ['label' => 'your own account: every field answers',
                 'query' => "{\n  me { id username email ssn apiToken privateNote }\n}"],
                ['label' => 'someone else\'s account, several fields at once',
                 'query' => "{\n  user(id: 1) { id username name role email ssn privateNote }\n}"],
                ['label' => 'the field list for User',
                 'query' => "{\n  __type(name: \"User\") { fields { name description } }\n}"],
            ],
        ]),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'Three resolvers asked permission. The fourth did not.',
    'why'      => '<p>The object-level check ran and said no: the row came back with
        <code>_authorised = false</code>. Every field resolver that consults that flag refused. The
        <code>apiToken</code> resolver does not consult it - it takes the id off the parent row, runs its own
        <code>SELECT</code>, and returns the column.</p>
        <p>By selecting only that field you avoided every resolver that would have objected. The check was never
        bypassed; it was not on the path your query took.</p>',

    'pipeline' => $stages,
    'probes'   => [
        'param'  => 'query',
        'method' => 'POST',
        'action' => 'level4.php',
        'items'  => [
            ['q' => 'Was the level-3 bug really fixed?',
             'payload' => '{ user(id: 1) { privateNote } }',
             'learn'   => 'If this now refuses, the object-level decision exists. That tells you to stop
                           attacking the object and start comparing its fields.'],
            ['q' => 'Which fields on a foreign account refuse, and which answer?',
             'payload' => '{ user(id: 1) { id username name role email } }',
             'learn'   => 'One request, five answers. The <code>path</code> in each error names the exact
                           resolver that objected, so the response is a map of the guard.'],
            ['q' => 'Does the field I care about work on my own account?',
             'payload' => '{ me { username apiToken } }',
             'learn'   => 'Confirm the field resolves at all before you test it against someone else. A field
                           that fails everywhere is a dead end, not a finding.'],
        ],
    ],
    'hints' => gq_hints($L),
]);
