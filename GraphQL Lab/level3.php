<?php
require_once __DIR__ . '/helpers.php';

$L    = 3;
$meta = gq_levels()[$L];

$sessionUser = 2;                                   // you are "guest"
$query       = (string)($_POST['query'] ?? '');
$flag        = '';
$result      = '';
$stages      = [];

if (trim($query) !== '') {
    $report = gql_execute(gq_schema_l3($sessionUser), $query, [
        'introspection' => true,
        'suggestions'   => true,
        'context'       => ['session_user_id' => $sessionUser],
    ]);
    $json   = gql_json($report['result']);
    $stages = gq_stages([[
        'label' => 'session established by the cookie',
        'value' => 'session_user_id = ' . $sessionUser . '  (username "guest")',
        'note'  => 'Authentication succeeded. That is a statement about who you are, not about what you may read.',
        'verdict' => 'pass',
    ], [
        'label' => 'POST /graphql',
        'value' => json_encode(['query' => $query], JSON_UNESCAPED_SLASHES),
    ]], $report['trace']);

    if (gql_data_contains($report['result'], gq_secret(3))) {
        $flag   = gq_flag($L);
        $result = '<div class="message success">Another account\'s private note is in your response body.</div>';
    } elseif (isset($report['result']['errors'])) {
        $result = '<div class="message error">The endpoint returned errors.</div>';
    } else {
        $result = '<div class="message info">Valid response. Nothing in it belongs to anyone but you yet.</div>';
    }
    $result .= gq_response_box($json);
}

$code = <<<'PHP'
// Query.user - "look up an account by id"
'user' => [
    'type' => 'User',
    'args' => ['id' => ['type' => 'Int!']],
    'resolve' => function ($root, $args, $ctx) {
        $id = (int) $args['id'];

        // The argument is validated: Int!, present, non-null. Then it is used.
        return $db->query('SELECT * FROM users WHERE id = ' . $id)->fetch();
    },
],

// User.privateNote - "only the account owner should read this"
'privateNote' => [
    'type'    => 'String',
    'resolve' => fn ($user) => $user['private_note'],
],

// $ctx['session_user_id'] is available on every resolver call.
// Search this file for it. It is not used.
PHP;

$fixBad = <<<'PHP'
'resolve' => function ($root, $args, $ctx) {
    return $db->query('SELECT * FROM users WHERE id = ' . (int) $args['id'])->fetch();
},
PHP;

$fixGood = <<<'PHP'
'resolve' => function ($root, $args, $ctx) {
    $id   = (int) $args['id'];
    $user = $repo->find($id);
    if (!$user) {
        return null;
    }

    // Every object reference the client can name needs a decision, here,
    // before the object leaves the resolver.
    if (!$ctx['viewer']->canView($user)) {
        throw new GqlError('Not authorised to read user ' . $id . '.');
    }
    return $user;
},
PHP;

lk_page([
    'lab'        => gqlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => gq_extra_head(),
    'extra_body' => gq_editor_script(),

    'code'       => $code,
    'vuln_lines' => [7, 8, 9],
    'annotation' => 'The resolver takes an object id from the client, loads that object, and returns it. The
        session identity is available on <code>$ctx</code> and is never compared with the requested id, so any
        authenticated user can name any row.',

    'theory' => '<p>This is insecure direct object reference, and it is worth saying that plainly:
        <strong>GraphQL IDOR is IDOR</strong>. The only thing that changed is where the object reference lives.
        In REST it is a path segment, <code>GET /api/users/3</code>. Here it is a typed argument,
        <code>user(id: 3)</code>. The missing check is identical, and so is the fix.</p>
        <p>What GraphQL adds is reach. A single schema exposes many entry points to the same object - a root
        field, a field on another type, a connection, a mutation payload - and each one is a separate resolver
        that has to make the decision independently. A team that patches <code>Query.user</code> often leaves
        <code>Query.document(id:) { owner { … } }</code> pointing at the same rows with no check at all.</p>
        <p>Two habits follow. First, when you test, enumerate <em>paths to the object</em>, not only root fields.
        Second, when you build, put the decision on the object or its repository rather than on each resolver,
        so a new path cannot be added without inheriting it.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Doing the check inside a repository or policy object beats doing it in each resolver: the next
            resolver that loads a user gets the check for free instead of having to remember it. Level 4 is what
            "remember it" looks like when someone forgets.',
    ],

    'scenario' => '<strong>Scenario:</strong> the account API lets a signed-in user look up an account by id, and
        <code>privateNote</code> is documented as owner-only.
        <br><strong>Goal:</strong> you are user #2. Read the private note belonging to another account.',

    'model' => [
        'title' => 'Three things that are often confused',
        'html'  => '<table class="lk-kv">
            <tr><td>authentication</td><td>the session cookie proves you are user #2. Done, and correct.</td></tr>
            <tr><td>validation</td><td><code>id</code> is an <code>Int!</code> and it was supplied. Done, and
                correct.</td></tr>
            <tr><td>authorisation</td><td>may user #2 read <em>this</em> row? Never asked.</td></tr>
        </table>
        <p>The first two produce reassuring green checks in a test suite. Only the third one is a security
        control, and it is the only one this endpoint does not perform.</p>
        <p>User ids on this service are small integers, so enumeration costs nothing. That is normal;
        unguessable ids slow an attacker down but they are not authorisation either.</p>',
    ],

    'form' => gq_identity('You are signed in as <code>guest</code>, user <strong>#2</strong>. There are five
        accounts, ids 1 to 5.')
        . gq_editor([
            'action'   => 'level3.php',
            'query'    => $query !== '' ? $query : "{\n  me { id username email privateNote }\n}",
            'examples' => [
                ['label' => 'your own account, which you are entitled to read',
                 'query' => "{\n  me { id username email role privateNote }\n}"],
                ['label' => 'the same fields through the lookup field',
                 'query' => "{\n  user(id: 2) { id username email privateNote }\n}"],
                ['label' => 'what the type offers',
                 'query' => "{\n  __type(name: \"User\") { fields { name description } }\n}"],
            ],
        ]),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The object reference was attacker-controlled and nothing compared it with the session.',
    'why'      => '<p>You changed one integer. The resolver built its query from that integer, the row came back,
        and <code>privateNote</code> returned the column it always returns, because that field resolver has no
        idea whose row it is holding.</p>
        <p>The trace shows the important detail: the session id and the requested id both existed inside the same
        function call, and no line of code brought them together.</p>',

    'pipeline' => $stages,
    'probes'   => [
        'param'  => 'query',
        'method' => 'POST',
        'action' => 'level3.php',
        'items'  => [
            ['q' => 'Does the lookup field work for my own id?',
             'payload' => '{ user(id: 2) { id username } }',
             'learn'   => 'Establish the baseline. If your own id works through <code>user(id:)</code>, the field
                           resolves rows by argument rather than by session.'],
            ['q' => 'Does an id that does not exist error, or return null?',
             'payload' => '{ user(id: 99) { id username } }',
             'learn'   => 'A null tells you the resolver returns whatever the query found, with no policy layer
                           in between. An error would hint that something is inspecting the result.'],
            ['q' => 'Which fields on User are marked as owner-only?',
             'payload' => '{ __type(name: "User") { fields { name description } }}',
             'learn'   => 'Descriptions are written for developers and often say exactly which field is
                           sensitive. Read them before you start selecting fields at random.'],
        ],
    ],
    'hints' => gq_hints($L),
]);
