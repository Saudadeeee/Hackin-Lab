<?php
require_once __DIR__ . '/helpers.php';

$L    = 9;
$meta = gq_levels()[$L];

$query  = (string)($_POST['query'] ?? '');
$flag   = '';
$result = '';
$stages = [];
$filter = '';

if (trim($query) !== '') {
    $report = gql_execute(gq_schema_l9(), $query, [
        'introspection' => true,
        'suggestions'   => true,
    ]);
    $json = gql_json($report['result']);

    // Pull the filter argument back out of the trace so the sink box can show
    // the exact string that reached the query.
    foreach ($report['trace']->events as $ev) {
        if (strpos($ev['label'], 'searchDocuments') !== false
            && preg_match("/LIKE '%(.*)%'\$/s", $ev['value'], $m)) {
            $filter = $m[1];
        }
    }

    $stages = gq_stages([[
        'label' => 'POST /graphql',
        'value' => json_encode(['query' => $query], JSON_UNESCAPED_SLASHES),
    ]], $report['trace'], [[
        'label' => 'what the type system checked about the argument',
        'value' => 'filter: String!  ->  present: yes, type: string, null: no',
        'note'  => 'That is the complete list. <code>String!</code> is a statement about the <em>shape</em> of
                    the value, and there is no part of the GraphQL specification that inspects its content.',
        'verdict' => 'pass',
    ]]);

    if (gql_data_contains($report['result'], gq_secret(9))) {
        $flag   = gq_flag($L);
        $result = '<div class="message success">A column the schema does not expose is in your response.</div>';
    } elseif (isset($report['result']['errors'])) {
        $result = '<div class="message error">Errors. If one of them is a SQLite message, read it carefully:
                   the database is telling you about its own parse of your string.</div>';
    } else {
        $result = '<div class="message info">The search ran and returned only what the schema exposes.</div>';
    }
    $result .= gq_response_box($json);
}

$code = <<<'PHP'
// Query.searchDocuments - free-text search over the caller's documents.
'searchDocuments' => [
    'type' => '[Document]',
    'args' => ['filter' => ['type' => 'String!']],
    'resolve' => function ($root, $args, $ctx) {
        $filter = (string) $args['filter'];

        // The argument arrived validated: it is present, and it is a string.
        // Nothing has looked inside it, and nothing is about to.
        $sql = "SELECT id, title, body FROM documents
                WHERE title LIKE '%" . $filter . "%'";

        return $db->query($sql)->fetchAll();
    },
],

// The table has a column the schema never mentions:
//   documents(id, owner_id, title, body, secret_note)
// 'Document' exposes id, title and body. secret_note is not a GraphQL field
// at all - which is exactly why a UNION can still return it.
PHP;

$fixBad = <<<'PHP'
$sql = "SELECT id, title, body FROM documents
        WHERE title LIKE '%" . $filter . "%'";
return $db->query($sql)->fetchAll();
PHP;

$fixGood = <<<'PHP'
// Bind the value. The driver sends the string as data, on its own, and the
// database never parses it as SQL - regardless of what it contains.
$st = $db->prepare(
    'SELECT id, title, body FROM documents
      WHERE owner_id = :owner AND title LIKE :pattern'
);
$st->execute([
    ':owner'   => $ctx['viewer']->id,      // and scope the rows while you are here
    ':pattern' => '%' . $filter . '%',
]);
return $st->fetchAll();

// If a custom scalar is wanted for input hygiene, write it as a scalar with a
// parseValue() that rejects, not as a comment on the argument. A type only
// constrains content if some code makes it.
PHP;

lk_page([
    'lab'        => gqlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => gq_extra_head(),
    'extra_body' => gq_editor_script(),

    'code'       => $code,
    'vuln_lines' => [10, 11],
    'annotation' => 'The resolver concatenates a <code>String!</code> argument into a SQL statement. The quotes
        around it belong to the developer; everything between them is supplied by the client, including
        apostrophes. The <code>documents</code> table has a <code>secret_note</code> column that is not a field
        on any GraphQL type, which does not put it out of reach of a UNION.',

    'theory' => '<p>GraphQL is often described as safe from injection because it is strongly typed. It is worth
        being precise about what the type system does: it checks that an argument is present when it is required,
        that a value is a string rather than a list or an object, and that an enum value is one of the declared
        members. It performs no content inspection whatsoever. <code>String!</code> and
        <code>"\' UNION SELECT …"</code> are entirely compatible claims.</p>
        <p>Where GraphQL genuinely helps is at the edges - it removes the ambiguity of parsing query strings and
        form bodies, so the value that reaches your resolver is unmistakably one string. Everything after that is
        the same as it has always been. A resolver is a controller; a sink is a sink. The same applies to NoSQL
        query documents, LDAP filters, shell arguments, template strings, and file paths built from arguments.</p>
        <p>Two details make GraphQL injection distinctive in practice. First, the schema shows you the argument
        names and their types, so you know what to reach for. Second, the response separates <code>data</code>
        from <code>errors</code>, and a resolver that leaks the database error message gives you a precise,
        readable oracle - column counts, table names, syntax positions - one request at a time.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Note the <code>owner_id</code> clause in the patched version. Parameter binding stops the
            injection; scoping the rows to the caller is what stops the query returning documents that were never
            theirs, which is the level-3 lesson turning up again in a different resolver.',
    ],

    'scenario' => '<strong>Scenario:</strong> document search takes a free-text filter and matches it against
        titles. The restricted drawing set is row 3, and its sensitive column is not exposed by the schema.
        <br><strong>Goal:</strong> get <code>secret_note</code> into the response through the
        <code>filter</code> argument.',

    'model' => [
        'title' => 'What the statement has to end up looking like',
        'html'  => '<p>Template, with your argument in the highlighted position:</p>
        <pre class="lk-sinkline">SELECT id, title, body FROM documents WHERE title LIKE \'%<span class="lk-inj">HERE</span>%\'</pre>
        <p>A UNION has to match the column count of the first SELECT - three here - and the response only shows
        you the columns the <code>Document</code> type declares. So put the interesting column in a position the
        schema does expose:</p>
        <pre class="lk-sinkline">SELECT id, title, body FROM documents WHERE title LIKE \'%x\' UNION SELECT id, secret_note, body FROM documents-- %\'</pre>
        <table class="lk-kv">
            <tr><td><code>x</code></td><td>matches no title, so only the union rows come back</td></tr>
            <tr><td><code>UNION SELECT id, secret_note, body</code></td><td>three columns; the second one lands
                in <code>title</code></td></tr>
            <tr><td><code>-- </code></td><td>comments out the developer\'s trailing <code>%\'</code>. SQLite
                wants whitespace after the two dashes.</td></tr>
        </table>
        <p>Escaping inside a GraphQL string literal follows JSON rules: a double quote is <code>\\"</code>, a
        backslash is <code>\\\\</code>, and a single quote needs no escaping at all.</p>',
    ],

    'form' => gq_identity('The trace prints the finished SQL statement for every request, so you can see the
        effect of each character you add.')
        . gq_editor([
            'action'   => 'level9.php',
            'query'    => $query !== '' ? $query : "{\n  searchDocuments(filter: \"dock\") { id title body }\n}",
            'examples' => [
                ['label' => 'an ordinary search',
                 'query' => "{\n  searchDocuments(filter: \"dock\") { id title body }\n}"],
                ['label' => 'everything the filter matches when it is empty',
                 'query' => "{\n  searchDocuments(filter: \"\") { id title }\n}"],
                ['label' => 'what the Document type exposes',
                 'query' => "{\n  __type(name: \"Document\") { fields { name type { name } } }\n}"],
            ],
        ]),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'A typed argument carried an untyped payload.',
    'why'      => '<p>Your apostrophe closed the developer\'s string literal, the <code>UNION</code> added rows
        the <code>WHERE</code> clause never selected, and the comment removed the tail of the original statement.
        The resolver returned whatever rows the statement produced, and the executor mapped the second column
        onto <code>Document.title</code> because that is the position it occupies.</p>
        <p>The schema was obeyed exactly. <code>Document</code> still has three fields, and
        <code>secret_note</code> is still not one of them - it arrived in the slot where
        <code>title</code> was expected. Validation happens on the query document; the SQL was built afterwards,
        by hand.</p>',

    'pipeline' => $stages,
    'sink'     => $filter !== '' ? [
        'label'    => 'the statement handed to SQLite',
        'before'   => "SELECT id, title, body FROM documents WHERE title LIKE '%",
        'injected' => $filter,
        'after'    => "%'",
    ] : null,
    'probes'   => [
        'param'  => 'query',
        'method' => 'POST',
        'action' => 'level9.php',
        'items'  => [
            ['q' => 'Does an apostrophe reach the SQL parser?',
             'payload' => '{ searchDocuments(filter: "\'") { id title } }',
             'learn'   => 'A SQLite syntax error in the errors array is a yes, and it proves the string is being
                           concatenated rather than bound. One request, one fact.'],
            ['q' => 'How many columns does the SELECT return?',
             'payload' => '{ searchDocuments(filter: "x\' UNION SELECT 1-- ") { id title } }',
             'learn'   => 'A deliberate mismatch. SQLite names the expected count in the error, so you never
                           have to count upwards one column at a time.'],
            ['q' => 'Which columns does the table really have?',
             'payload' => '{ searchDocuments(filter: "x\' UNION SELECT 1, (SELECT group_concat(name) FROM pragma_table_info(\'documents\')), 3-- ") { id title } }',
             'learn'   => 'SQLite exposes its own metadata through pragma functions. Reading the column list
                           first turns the next step from a guess into a lookup.'],
        ],
    ],
    'hints' => gq_hints($L),
]);
