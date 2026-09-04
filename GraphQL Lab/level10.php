<?php
require_once __DIR__ . '/helpers.php';

$L    = 10;
$meta = gq_levels()[$L];

if (!empty($_POST['_reset'])) {
    gq_reset_state();
    header('Location: level10.php');
    exit;
}

/** Same registry as level 6, one more entry. */
$PROTECTED = ['GrantRole' => 'admin', 'RotateKeys' => 'admin', 'DeleteUser' => 'admin'];

$sessionUser = 4;                                   // "operator"
$sessionRole = (string)(gq_user($sessionUser)['role'] ?? 'analyst');

$query  = (string)($_POST['query'] ?? '');
$opName = trim((string)($_POST['operationName'] ?? ''));
$flag   = '';
$result = '';
$stages = [];

if (trim($query) !== '') {
    $needed  = ($opName !== '' && isset($PROTECTED[$opName])) ? $PROTECTED[$opName] : null;
    $blocked = $needed !== null && $sessionRole !== $needed;

    $stages[] = [
        'label' => 'POST /graphql  request body',
        'value' => json_encode(
            $opName !== '' ? ['query' => $query, 'operationName' => $opName] : ['query' => $query],
            JSON_UNESCAPED_SLASHES
        ),
    ];
    $stages[] = [
        'label'   => 'guard: $PROTECTED[$body["operationName"]]',
        'value'   => 'operationName = ' . ($opName === '' ? '(absent)' : '"' . $opName . '"')
                     . '   ->   required role: ' . ($needed ?? '(not a protected operation)')
                     . '   ->   your role: ' . $sessionRole,
        'note'    => 'Unchanged since level 6. It reads the label on the envelope, not the document inside it.',
        'verdict' => $blocked ? 'block' : 'pass',
    ];

    if ($blocked) {
        $result = '<div class="message error">403 Forbidden &mdash; operation <code>' . lk_esc($opName)
                . '</code> requires role <code>' . lk_esc((string)$needed) . '</code>.</div>'
                . gq_response_box(gql_json(['errors' => [['message' =>
                    'Operation "' . $opName . '" requires role "' . $needed . '".']]]));
    } else {
        $report = gql_execute(gq_schema_l10($sessionUser), $query, [
            'introspection' => true,
            'suggestions'   => true,
            'operationName' => $opName !== '' ? $opName : null,
        ]);
        $json      = gql_json($report['result']);
        $roleAfter = (string)(gq_user($sessionUser)['role'] ?? '');

        $stages = gq_stages($stages, $report['trace'], [[
            'label'   => 'users.role for session user #' . $sessionUser . ', after this request',
            'value'   => $roleAfter,
            'note'    => 'Persisted. <code>Query.adminSettings</code> reads it fresh on every request, so the
                          escalation has to land before the read is sent.',
            'verdict' => $roleAfter === 'admin' ? 'pass' : null,
        ]]);

        if (gql_data_contains($report['result'], gq_secret(10))) {
            $flag   = gq_flag($L);
            $result = '<div class="message success">The vault key is in your response. Discovery, guard bypass
                       and a genuine role check, in that order.</div>';
        } elseif (isset($report['result']['errors'])) {
            $result = '<div class="message error">The endpoint returned errors.</div>';
        } elseif ($roleAfter === 'admin') {
            $result = '<div class="message info">Escalation done and persisted. Send the read now.</div>';
        } else {
            $result = '<div class="message info">Executed, nothing privileged in the response.</div>';
        }
        $result .= gq_response_box($json);
    }
}

$code = <<<'PHP'
// --- the operation-name guard, unchanged since the level-6 incident --------
$PROTECTED = ['GrantRole' => 'admin', 'RotateKeys' => 'admin', 'DeleteUser' => 'admin'];

$opName = $body['operationName'] ?? null;
if ($opName !== null && isset($PROTECTED[$opName])
    && $session->role !== $PROTECTED[$opName]) {
    return response(['errors' => [['message' => 'Forbidden']]], 403);
}

// --- the mutation it is supposed to be protecting --------------------------
'grantRole' => [
    'args'    => ['userId' => ['type' => 'Int!'], 'role' => ['type' => 'String!']],
    'resolve' => fn ($r, $a) => $repo->setRole((int) $a['userId'], (string) $a['role']),
],

// --- the field that does check, properly -----------------------------------
'adminSettings' => [
    'type'    => 'AdminSettings',
    'resolve' => function ($r, $a, $ctx) {
        // Re-read from the database. Not from the session, not from a token
        // claim minted at login - the current row, right now.
        $role = $repo->find($ctx['session_user_id'])['role'];
        if ($role !== 'admin') {
            throw new GqlError('Forbidden: adminSettings requires role "admin".');
        }
        return $repo->settings();
    },
],
PHP;

$fixBad = <<<'PHP'
$opName = $body['operationName'] ?? null;
if ($opName !== null && isset($PROTECTED[$opName])
    && $session->role !== $PROTECTED[$opName]) {
    return forbidden();
}
'grantRole' => ['resolve' => fn ($r, $a) => $repo->setRole(...)],
PHP;

$fixGood = <<<'PHP'
// The write needs the same standard of check as the read it eventually
// unlocks. Put it in the resolver, where nothing about the request framing
// can route around it.
'grantRole' => [
    'args'    => ['userId' => ['type' => 'Int!'], 'role' => ['type' => 'String!']],
    'resolve' => function ($r, $a, $ctx) {
        $actor = $repo->find($ctx['session_user_id']);
        if ($actor['role'] !== 'admin') {
            throw new GqlError('Forbidden: grantRole requires role "admin".');
        }
        // Grants are a step change in trust. Log them, and do not let an
        // account grant itself anything.
        if ((int) $a['userId'] === $actor['id']) {
            throw new GqlError('An account may not change its own role.');
        }
        audit('role.grant', $actor, $a);
        return $repo->setRole((int) $a['userId'], (string) $a['role']);
    },
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
    'vuln_lines' => [4, 5, 6, 7, 11, 12, 13, 14],
    'annotation' => 'Two of the three pieces are fine on their own. <code>adminSettings</code> performs a real
        check against the live database row, and the operation-name guard does block a request that declares a
        protected name. The gap is that the write which decides that row is protected only by the guard, and the
        guard reads a field the client may leave out.',

    'theory' => '<p>Chains are how findings become incidents. Each link here is small: introspection is a
        configuration choice, an operation-name guard is a design mistake that needs a specific request shape to
        exploit, and a role column is a column like any other. Reported separately, each one attracts a "low, no direct
        impact". Composed, they read the vault key.</p>
        <p>The ordering matters and it is worth naming. First discovery - you cannot call a field you cannot
        name, and this endpoint will tell you the name. Then the bypass - the guard is the only thing between you
        and the write, and it inspects a label rather than the document. Then escalation - the mutation changes
        persistent state, so the next request arrives with different rights. Only the last step touches a control
        that is implemented correctly, and by then it says yes.</p>
        <p>Notice that the correct check is what makes the chain worth building. <code>adminSettings</code> reads
        the role from the database on every request rather than trusting a session field or a token claim, which
        is exactly right - and it means an attacker who can write that row inherits everything the check would
        have granted. Strong reads make weak writes valuable. When you audit, follow the data that authorisation
        depends on, and ask who can change it.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The self-grant rule is not decoration. Role escalation to oneself is the single most common
            shape of this bug in real applications, and it is cheap to make impossible.',
    ],

    'scenario' => '<strong>Scenario:</strong> the internal operations console. You are <code>operator</code>,
        user <strong>#4</strong>, role <code>' . lk_esc($sessionRole) . '</code>. The console documents
        <code>me</code> and <code>adminSettings</code>; its mutations are not documented anywhere you can read.
        <br><strong>Goal:</strong> find the mutation, get it past the guard, and read
        <code>adminSettings.vaultKey</code>. It will take more than one request.',

    'model' => [
        'title' => 'The three links, and what each one needs',
        'html'  => '<table class="lk-kv">
            <tr><td>1. discovery</td><td>the mutation field name and its argument names. Introspection answers on
                this endpoint, and so does the suggestion list - either will do.</td></tr>
            <tr><td>2. bypass</td><td>the guard only fires on a protected <code>operationName</code>. Send the
                document without one.</td></tr>
            <tr><td>3. escalation</td><td>the mutation writes <code>users.role</code>, and that write survives the
                response. The next request is the one that reads the vault.</td></tr>
        </table>
        <p>Nothing here is solved in a single document: a GraphQL operation is either a query or a mutation, not
        both, so the write and the read are two requests. <em>Reset lab state</em> puts your role back to
        <code>analyst</code> if you want to replay the sequence.</p>',
    ],

    'form' => gq_identity('You are <code>operator</code>, user <strong>#4</strong>, current role <code>'
        . lk_esc($sessionRole) . '</code>.')
        . gq_editor([
            'action'         => 'level10.php',
            'reset'          => true,
            'operation_name' => true,
            'operation_name_value' => $opName,
            'query'          => $query !== '' ? $query : "{\n  me { id username role }\n}",
            'examples'       => [
                ['label' => 'what the console documents',
                 'query' => "{\n  me { id username name role }\n  adminSettings { region }\n}"],
                ['label' => 'ask what mutations exist',
                 'query' => "{\n  __type(name: \"Mutation\") {\n    fields { name description args { name type { name ofType { name } } } }\n  }\n}"],
                ['label' => 'the mutation, named the way the console names it',
                 'query' => "mutation GrantRole {\n  grantRole(userId: 4, role: \"admin\") { username role }\n}"],
            ],
        ]),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'Three findings, none of them critical on its own.',
    'why'      => '<p>Introspection named <code>grantRole</code> and its two arguments. Sending the mutation with
        no <code>operationName</code> left the guard with nothing to look up, so it allowed the request, and the
        resolver wrote <code>role = "admin"</code> onto your row. On the following request
        <code>adminSettings</code> did its check properly, read the row, found <code>admin</code>, and returned
        the settings including the vault key.</p>
        <p>Every component behaved as written. The escalation happened in the gap between a control that guards
        reads and a control that was supposed to guard writes but was measuring the wrong thing.</p>',

    'pipeline' => $stages,
    'probes'   => [
        'param'  => 'query',
        'method' => 'POST',
        'action' => 'level10.php',
        'items'  => [
            ['q' => 'What is my current role, and what does the protected read say about it?',
             'payload' => '{ me { id username role } adminSettings { region } }',
             'learn'   => 'The error message from <code>adminSettings</code> names the role it wants. That is
                           your objective, stated by the target.'],
            ['q' => 'What mutations does this endpoint have?',
             'payload' => '{ __type(name: "Mutation") { fields { name description args { name } } } }',
             'learn'   => 'Field name, argument names, and often a description that names the operation the
                           guard expects. Discovery in one request.'],
            ['q' => 'Does the mutation execute when the body carries no operationName?',
             'payload' => 'mutation { grantRole(userId: 4, role: "analyst") { username role } }',
             'learn'   => 'Grants you the role you already have, so nothing is escalated and the flag is not
                           awarded. A populated response proves the resolver ran, which is the only thing you
                           needed to know before choosing a different second argument.'],
        ],
    ],
    'hints' => gq_hints($L),
]);
