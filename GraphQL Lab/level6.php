<?php
require_once __DIR__ . '/helpers.php';

$L    = 6;
$meta = gq_levels()[$L];

if (!empty($_POST['_reset'])) {
    gq_reset_state();
    header('Location: level6.php');
    exit;
}

/** Operations the service treats as privileged, keyed by the name clients send. */
$PROTECTED = ['PromoteUser' => 'admin', 'DeleteUser' => 'admin', 'RotateKeys' => 'admin'];

$sessionUser = 5;                                   // "mreed", support desk
$sessionRole = (string)(gq_user($sessionUser)['role'] ?? 'support');

$query  = (string)($_POST['query'] ?? '');
$opName = trim((string)($_POST['operationName'] ?? ''));
$flag   = '';
$result = '';
$stages = [];

if (trim($query) !== '') {
    $roleBefore = (string)(gq_user($sessionUser)['role'] ?? '');

    // ── The middleware. It authorises the label the client attached to the
    //    request, not the operation the document contains. ─────────────────
    $needed  = ($opName !== '' && isset($PROTECTED[$opName])) ? $PROTECTED[$opName] : null;
    $blocked = $needed !== null && $sessionRole !== $needed;

    $stages[] = [
        'label' => 'POST /graphql  request body',
        'value' => json_encode(
            $opName !== '' ? ['query' => $query, 'operationName' => $opName] : ['query' => $query],
            JSON_UNESCAPED_SLASHES
        ),
        'note'  => 'Two independent places name the operation: the JSON field <code>operationName</code>, and the
                    document itself. Only one of them is a security input here.',
    ];
    $stages[] = [
        'label'   => 'guard: $PROTECTED[$body["operationName"]]',
        'value'   => 'operationName = ' . ($opName === '' ? '(absent)' : '"' . $opName . '"')
                     . '   ->   required role: ' . ($needed ?? '(not a protected operation)')
                     . '   ->   your role: ' . $sessionRole,
        'note'    => $blocked
            ? 'The lookup hit an entry and your role does not match, so the request stops here.'
            : 'The lookup found nothing to enforce, so the guard has no opinion and the request continues. It
               never opened the document.',
        'verdict' => $blocked ? 'block' : 'pass',
    ];

    if ($blocked) {
        $result = '<div class="message error">403 Forbidden &mdash; operation <code>' . lk_esc($opName)
                . '</code> requires role <code>' . lk_esc((string)$needed) . '</code>.</div>'
                . gq_response_box(gql_json(['errors' => [['message' =>
                    'Operation "' . $opName . '" requires role "' . $needed . '".']]]));
    } else {
        $report = gql_execute(gq_schema_l6($sessionUser), $query, [
            'introspection' => true,
            'suggestions'   => true,
            'operationName' => $opName !== '' ? $opName : null,
        ]);
        $json      = gql_json($report['result']);
        $roleAfter = (string)(gq_user($sessionUser)['role'] ?? '');

        $stages = gq_stages($stages, $report['trace'], [[
            'label'   => 'users.role for session user #' . $sessionUser . ', read back from the database',
            'value'   => 'before this request: ' . $roleBefore . '   after this request: ' . $roleAfter,
            'note'    => 'The flag is awarded for this transition, not for the text of the query. The write is
                          real and it persists until you reset the level.',
            'verdict' => $roleAfter === 'admin' ? 'pass' : null,
        ]]);

        if ($roleBefore !== 'admin' && $roleAfter === 'admin') {
            $flag   = gq_flag($L);
            $result = '<div class="message success">The mutation ran and your account is now
                       <code>admin</code> in the database.</div>';
        } elseif ($roleAfter === 'admin') {
            $result = '<div class="message info">Your account is already <code>admin</code> from an earlier
                       request. Press <em>Reset lab state</em> to put it back to <code>support</code> and replay
                       the escalation.</div>';
        } elseif (isset($report['result']['errors'])) {
            $result = '<div class="message error">The endpoint returned errors.</div>';
        } else {
            $result = '<div class="message info">The request executed and changed nothing privileged.</div>';
        }
        $result .= gq_response_box($json);
    }
}

$code = <<<'PHP'
// Operations that need elevated rights, keyed by the name clients send.
// The mobile and web clients are generated from this table, so in practice
// every privileged call arrives with the matching operationName.
$PROTECTED = [
    'PromoteUser' => 'admin',
    'DeleteUser'  => 'admin',
    'RotateKeys'  => 'admin',
];

$opName = $body['operationName'] ?? null;

if ($opName !== null && isset($PROTECTED[$opName])
    && $session->role !== $PROTECTED[$opName]) {
    return response(['errors' => [['message' => 'Forbidden']]], 403);
}

// The executor picks the operation out of the DOCUMENT. With no operationName
// supplied it runs the only operation there, whatever that operation is.
$report = gql_execute($schema, (string) $body['query'], [
    'operationName' => $opName,
]);

// Mutation.promoteUser has no authorisation code of its own.
'promoteUser' => [
    'args'    => ['id' => ['type' => 'Int!'], 'role' => ['type' => 'String!']],
    'resolve' => fn ($r, $a) => $repo->setRole((int) $a['id'], (string) $a['role']),
],
PHP;

$fixBad = <<<'PHP'
$opName = $body['operationName'] ?? null;
if ($opName !== null && isset($PROTECTED[$opName])
    && $session->role !== $PROTECTED[$opName]) {
    return forbidden();
}
PHP;

$fixGood = <<<'PHP'
// Authorise the field that will actually run, in the resolver that runs it.
'promoteUser' => [
    'args'    => ['id' => ['type' => 'Int!'], 'role' => ['type' => 'String!']],
    'resolve' => function ($r, $a, $ctx) {
        $ctx['viewer']->require('user.role.write');   // throws, no bypass path
        return $repo->setRole((int) $a['id'], (string) $a['role']);
    },
],

// If a central policy is wanted, key it on the parsed document rather than on
// a label from the body - and default to deny for anything unrecognised.
$doc = parse($body['query']);
foreach (root_fields_of($doc, $body['operationName'] ?? null) as $field) {
    $policy->requireFor($field, $session);            // unknown field -> deny
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
    'vuln_lines' => [11, 13, 14, 15, 16],
    'annotation' => 'The guard authorises <code>$body["operationName"]</code>, a label the client writes. The
        executor runs whatever operation the <em>document</em> contains. When the label is absent the lookup finds
        nothing, the guard has no opinion, and the unnamed mutation runs with no check anywhere.',

    'theory' => '<p>Two names for the same request is one name too many. The JSON field
        <code>operationName</code> exists to disambiguate a document that carries several operations; it is a
        routing hint, supplied by the client, and it is optional. The document is the request. A guard that reads
        the hint and not the document is authorising a claim rather than an action.</p>
        <p>The failure mode is not "the attacker lied about the name" so much as "the attacker declined to say
        one". The lookup is a positive check - it only fires on a known key - so anything not in the table sails
        through. Defaulting to allow is what makes an omission into a bypass, and it is the same shape as a WAF
        rule list, an <code>if (isset($rules[$path]))</code> route guard, or a permission map keyed on a
        client-supplied action string.</p>
        <p>Two habits when testing a GraphQL endpoint: send the same document with and without
        <code>operationName</code> and compare, and rename operations. If <code>mutation Foo</code> and
        <code>mutation PromoteUser</code> behave differently, the authorisation is reading the name.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The resolver-level fix is the one that cannot be routed around: whatever the client calls the
            operation, that resolver is where the write happens. A central policy is still useful, but only if it
            reads the parsed document and denies by default.',
    ],

    'scenario' => '<strong>Scenario:</strong> you are <code>mreed</code> on the support desk, role
        <code>support</code>. The admin console calls <code>PromoteUser</code> to change roles, and that operation
        name is in the protected table.
        <br><strong>Goal:</strong> run the privileged mutation and end the request with role <code>admin</code>
        in the database.',

    'model' => [
        'title' => 'What the request actually contains',
        'html'  => '<p>A GraphQL POST body has three top-level fields, and they are independent:</p>
        <pre class="lk-sinkline">{"query": "mutation PromoteUser { promoteUser(id: 5, role: \\"admin\\") { role } }",
 "operationName": "PromoteUser",
 "variables": {}}</pre>
        <table class="lk-kv">
            <tr><td><code>query</code></td><td>the document. This is what runs.</td></tr>
            <tr><td><code>operationName</code></td><td>which operation in the document to run. Optional; only
                needed when the document holds more than one.</td></tr>
            <tr><td>the operation\'s own name</td><td>written inside the document, after
                <code>mutation</code>. Also optional.</td></tr>
        </table>
        <p>An anonymous operation - <code>mutation { … }</code> - is complete and legal. The editor below sends
        <code>operationName</code> only when you type something into the second box.</p>',
    ],

    'form' => gq_identity('You are <code>mreed</code>, user <strong>#5</strong>, current role <code>'
        . lk_esc($sessionRole) . '</code>. <em>Reset lab state</em> puts the role back to <code>support</code>.')
        . gq_editor([
            'action'         => 'level6.php',
            'reset'          => true,
            'operation_name' => true,
            'operation_name_value' => $opName,
            'query'          => $query !== '' ? $query : "{\n  me { id username role }\n}",
            'note'           => 'Leave the second box empty and no <code>operationName</code> is sent with the
                                 request at all.',
            'examples'       => [
                ['label' => 'read your own account',
                 'query' => "{\n  me { id username name role }\n}"],
                ['label' => 'a harmless mutation, to see that mutations reach the executor',
                 'query' => "mutation {\n  updateDisplayName(name: \"Morgan R\") { id name }\n}"],
                ['label' => 'the privileged one, named the way the admin console names it',
                 'query' => "mutation PromoteUser {\n  promoteUser(id: 5, role: \"admin\") { username role }\n}"],
            ],
        ]),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The write happened because the guard was asked about a label that was never sent.',
    'why'      => '<p>With the operation-name box empty, the request body carried no <code>operationName</code>.
        The guard looked it up in <code>$PROTECTED</code>, found nothing, and allowed the request. The executor
        then took the only operation in the document - your mutation - and ran it. The resolver has no
        authorisation code, so the <code>UPDATE</code> executed.</p>
        <p>Compare the two traces. Send the same document with <code>PromoteUser</code> in the box and the guard
        blocks it; the difference between forbidden and permitted is a string you control and may omit.</p>',

    'pipeline' => $stages,
    'probes'   => [
        'param'  => 'query',
        'method' => 'POST',
        'action' => 'level6.php',
        'items'  => [
            ['q' => 'Do mutations reach the executor at all from this account?',
             'payload' => 'mutation { updateDisplayName(name: "probe") { id name } }',
             'learn'   => 'A harmless write. If it lands, mutations are not blocked as a class and the guard must
                           be keyed on something narrower.'],
            ['q' => 'Does the privileged resolver exist, and what does it take?',
             'payload' => '{ __type(name: "Mutation") { fields { name description args { name } } } }',
             'learn'   => 'Argument names and the description, in one request. The description often says
                           outright which operation name the guard expects.'],
            ['q' => 'Does the privileged mutation run when it changes nothing?',
             'payload' => 'mutation { promoteUser(id: 5, role: "support") { username role } }',
             'learn'   => 'Sets your role to the value it already has, so nothing is escalated. If the response
                           comes back populated, the resolver ran and only the guard stood between you and a
                           different second argument.'],
        ],
    ],
    'hints' => gq_hints($L),
]);
