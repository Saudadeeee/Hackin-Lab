<?php
require_once __DIR__ . '/helpers.php';

$L    = 2;
$meta = gq_levels()[$L];

$query  = (string)($_POST['query'] ?? '');
$flag   = '';
$result = '';
$stages = [];

if (trim($query) !== '') {
    // ── Introspection is off. The suggestion list in the error handler is not. ──
    $report = gql_execute(gq_schema_l2(), $query, [
        'introspection' => false,
        'suggestions'   => true,
    ]);
    $json   = gql_json($report['result']);

    $errs = $report['result']['errors'] ?? [];
    $names = [];
    foreach ($errs as $e) {
        if (preg_match_all('/Did you mean (.+)\?$/', $e['message'], $m)) {
            $names[] = $m[1][0];
        }
    }
    $stages = gq_stages([[
        'label' => 'POST /graphql',
        'value' => json_encode(['query' => $query], JSON_UNESCAPED_SLASHES),
        'note'  => 'The same endpoint as level 1, with one configuration flag changed.',
    ]], $report['trace'], [[
        'label'   => 'introspection flag on this endpoint',
        'value'   => 'introspection = false',
        'note'    => '<code>__schema</code> and <code>__type</code> are not registered as fields, so they fail
                      validation like any other unknown name.',
        'verdict' => 'block',
    ], [
        'label'   => 'error handler: suggestion list',
        'value'   => $names ? implode(' | ', $names) : '(no suggestion produced for this document)',
        'note'    => 'Built by scoring the name you sent against every real field name of that type. Each
                      rejected guess returns a little of the schema you were not allowed to read.',
        'verdict' => $names ? 'pass' : null,
    ]]);

    if (gql_data_contains($report['result'], gq_secret(2))) {
        $flag   = gq_flag($L);
        $result = '<div class="message success">The on-call PIN came back in the response body.</div>';
    } elseif ($errs) {
        $result = '<div class="message error">Errors, which on this endpoint are the useful part. Read the
                   suggestions.</div>';
    } else {
        $result = '<div class="message info">Valid response, but not the field that holds the PIN.</div>';
    }
    $result .= gq_response_box($json);
}

$code = <<<'PHP'
// Hardening ticket SEC-118: "disable introspection in production".
$report = gql_execute($schema, (string) $body['query'], [
    'introspection' => false,     // done
    'suggestions'   => true,      // untouched - it is a developer-experience setting
]);

// ---- inside the validator, when a field name does not resolve -------------
function unknown_field_message(string $field, string $type, array $realFields): string
{
    $msg = 'Cannot query field "' . $field . '" on type "' . $type . '".';

    // Rank every real field name of that type against what the client sent.
    $hits = suggest($field, $realFields);          // edit distance + substring
    if ($hits) {
        $msg .= ' Did you mean ' . quoted_list($hits) . '?';
    }
    return $msg;
}
PHP;

$fixBad = <<<'PHP'
$msg  = 'Cannot query field "' . $field . '" on type "' . $type . '".';
$msg .= ' Did you mean ' . quoted_list(suggest($field, $realFields)) . '?';
return $msg;
PHP;

$fixGood = <<<'PHP'
// In production, an unauthenticated client gets a stable, contentless error.
// The detailed one goes to the log, where the developer who needs it is.
if ($env === 'production' && !$viewer->isStaff()) {
    log_validation_error($field, $type, $realFields, $requestId);
    return 'GraphQL validation failed. Request id: ' . $requestId;
}
return 'Cannot query field "' . $field . '" on type "' . $type . '".'
     . ' Did you mean ' . quoted_list(suggest($field, $realFields)) . '?';
PHP;

lk_page([
    'lab'        => gqlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => gq_extra_head(),
    'extra_body' => gq_editor_script(),

    'code'       => $code,
    'vuln_lines' => [4, 12, 13, 14, 15, 16],
    'annotation' => 'Introspection is off, so the schema cannot be dumped in one request. The validator still
        answers every rejected field name with a ranked list of the real field names on that type, which turns the
        error channel into the same oracle one guess at a time.',

    'theory' => '<p>Disabling introspection is worth doing, and it is routinely mistaken for making the schema
        secret. It is not, because a GraphQL server has to reject invalid documents, and a rejection is a fact
        about the schema. "That field does not exist" already narrows the space; "did you mean X" collapses it.</p>
        <p>The suggestion algorithm is the leak. It scores your guess against the true field list, so a guess that
        is merely <em>near</em> a real name pulls that name out. In practice a handful of common words
        (<code>user</code>, <code>admin</code>, <code>token</code>, <code>note</code>, <code>key</code>) plus the
        words visible in the UI recover most of a schema, and public tools automate exactly this.</p>
        <p>The general shape is worth carrying to other targets: any interface that compares your input against
        secret data and reports how close you were is an oracle. Password reset forms that say "no such user",
        login endpoints with different timings, and validators with spelling help are the same bug wearing
        different clothes.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The point is not that suggestions are bad - they are excellent in development. The point is
            that error verbosity is an audience decision, and the audience of a production endpoint is everyone.',
    ],

    'scenario' => '<strong>Scenario:</strong> the team closed the introspection ticket after level 1 and shipped.
        Everything else about the endpoint is unchanged.
        <br><strong>Goal:</strong> recover the name of a hidden root field and the name of the field on its type
        that holds the Zurich rack on-call PIN, using error messages only, then read the PIN.',

    'model' => [
        'title' => 'What each rejected guess tells you',
        'html'  => '<p>Errors here come in three flavours, and each one is a different fact:</p>
        <table class="lk-kv">
            <tr><td><code>Cannot query field "x" on type "Query".</code></td>
                <td>no root field is close to <code>x</code></td></tr>
            <tr><td><code>… Did you mean "staffNotes"?</code></td>
                <td>a real root field, spelled for you</td></tr>
            <tr><td><code>Field "y" of type "String" must not have a selection set.</code></td>
                <td><code>y</code> exists and is a scalar, so stop nesting into it</td></tr>
        </table>
        <p>The scoring favours substrings, so short guesses that could sit inside a longer camelCase name work
        best: <code>note</code>, <code>pin</code>, <code>key</code>, <code>token</code>, <code>secret</code>.
        Guess on the type you are already inside - each type has its own field list.</p>',
    ],

    'form' => gq_identity('Same storefront, same account. <code>__schema</code> now fails validation, so the map
        has to be rebuilt from the rejections.')
        . gq_editor([
            'action'   => 'level2.php',
            'query'    => $query !== '' ? $query : "{\n  notes\n}",
            'examples' => [
                ['label' => 'confirm introspection really is off',
                 'query' => "{\n  __schema { types { name } }\n}"],
                ['label' => 'a guess at a root field',
                 'query' => "{\n  notes\n}"],
                ['label' => 'a guess at a field inside a type you have found',
                 'query' => "{\n  staffNotes { pin }\n}"],
            ],
        ]),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The schema was rebuilt out of its own error messages.',
    'why'      => '<p>Every wrong name you sent was compared against the true field list of the type you sent it
        on, and the comparison was reported back to you. Two rejections were enough: one named the root field,
        one named the field on its type.</p>
        <p>The endpoint never granted you access to the schema. It granted you a distance measurement against the
        schema, repeatedly, for free - and that is the same thing with more steps.</p>',

    'pipeline' => $stages,
    'probes'   => [
        'param'  => 'query',
        'method' => 'POST',
        'action' => 'level2.php',
        'items'  => [
            ['q' => 'Is introspection disabled, or only undocumented?',
             'payload' => '{ __schema { types { name } } }',
             'learn'   => 'Establish the ground rules before you start guessing. A "Cannot query field
                           __schema" here means the rest of this level is the only route.'],
            ['q' => 'Does the error handler suggest at all?',
             'payload' => '{ produkts { id } }',
             'learn'   => 'A deliberate typo of a field you already know exists. If the suggestion comes back,
                           the oracle is live and you can start using it on words you do not know.'],
            ['q' => 'Do suggestions work inside a nested type as well as the root?',
             'payload' => '{ me { nam } }',
             'learn'   => 'Field lists are per type. Confirming that the oracle follows you down into
                           <code>User</code> tells you it will follow you into every other type too.'],
        ],
    ],
    'hints' => gq_hints($L),
]);
