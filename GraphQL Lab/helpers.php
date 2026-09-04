<?php
/**
 * GraphQL Lab · lab metadata, flags, hints and the shared level UI.
 */

require_once __DIR__ . '/lab_kit.php';
require_once __DIR__ . '/schema.php';

function gqlab(): array
{
    return [
        'slug'    => 'graphql',
        'name'    => 'GraphQL Lab',
        'icon'    => 'GQL',
        'total'   => 10,
        'tagline' => 'The query was valid. Nobody asked whether the data was allowed.',
    ];
}

function gq_flag(int $level): string
{
    $flags = [
        1  => 'FLAG{introspection_maps_the_attack_surface}',
        2  => 'FLAG{error_suggestions_rebuild_the_schema}',
        3  => 'FLAG{graphql_idor_is_still_idor}',
        4  => 'FLAG{one_field_skipped_the_check}',
        5  => 'FLAG{aliases_multiply_operations_per_request}',
        6  => 'FLAG{the_guard_only_read_the_operation_name}',
        7  => 'FLAG{the_guard_inspected_only_batch_entry_zero}',
        8  => 'FLAG{fragments_expand_after_the_depth_count}',
        9  => 'FLAG{types_validate_shape_not_content}',
        10 => 'FLAG{introspect_then_bypass_then_escalate}',
    ];
    return $flags[$level] ?? '';
}

function gq_levels(): array
{
    return [
        1 => [
            'title'      => 'Introspection Is On',
            'difficulty' => 'Easy',
            'skill'      => '__schema, reading a server the UI never documented',
            'desc'       => 'The production endpoint answers introspection queries. The schema contains a type and a field the storefront bundle never mentions.',
        ],
        2 => [
            'title'      => 'Suggestions Leak the Schema',
            'difficulty' => 'Easy',
            'skill'      => 'Error messages as an oracle, schema recovery without __schema',
            'desc'       => 'Introspection is switched off, and the error handler still answers <code>Did you mean …</code>. One field name at a time, the schema comes back.',
        ],
        3 => [
            'title'      => 'Object-Level Authorisation',
            'difficulty' => 'Medium',
            'skill'      => 'IDOR through a resolver argument',
            'desc'       => '<code>user(id:)</code> returns whichever row you name because the resolver never compares that id with the session.',
        ],
        4 => [
            'title'      => 'Field-Level Authorisation',
            'difficulty' => 'Medium',
            'skill'      => 'Per-field resolvers that bypass the object-level decision',
            'desc'       => 'The object is authorised once, as a whole. One field resolver fetches its value on its own and never consults that decision.',
        ],
        5 => [
            'title'      => 'Aliases Defeat the Rate Limiter',
            'difficulty' => 'Medium',
            'skill'      => 'Aliasing, operations per request vs requests per minute',
            'desc'       => 'Five requests a minute, and every request may carry as many aliased calls to the same field as you like.',
        ],
        6 => [
            'title'      => 'Mutation Without Authorisation',
            'difficulty' => 'Hard',
            'skill'      => 'Guards keyed on a client-supplied label',
            'desc'       => 'The middleware authorises by looking up the request\'s <code>operationName</code> in a table of privileged operations. The document decides what actually runs.',
        ],
        7 => [
            'title'      => 'Batching Bypass',
            'difficulty' => 'Hard',
            'skill'      => 'Array request bodies, guards that inspect one element',
            'desc'       => 'The endpoint accepts an array of operations and executes all of them. The guard reads <code>$body[0]</code>.',
        ],
        8 => [
            'title'      => 'Depth Limit and the Fragment Loop',
            'difficulty' => 'Hard',
            'skill'      => 'Static analysis that runs before fragment expansion',
            'desc'       => 'A depth limiter counts nesting on the operation AST. Fragments are expanded afterwards, by the executor, and the two numbers disagree.',
        ],
        9 => [
            'title'      => 'Injection Through a Resolver',
            'difficulty' => 'Expert',
            'skill'      => 'SQL injection under a strongly typed argument',
            'desc'       => 'A resolver builds SQL by concatenating a <code>String!</code> argument. The type system checked the shape of the value and stopped there.',
        ],
        10 => [
            'title'      => 'Chain',
            'difficulty' => 'Expert',
            'skill'      => 'Discovery, guard bypass and privilege escalation in sequence',
            'desc'       => 'Find an undocumented mutation, get it past the operation-name guard, then read a field that checks your role for real.',
        ],
    ];
}

/* =========================================================================
 * Hints (5 per level: concept -> observation -> technique -> shape -> payload)
 * ===================================================================== */

function gq_hints(int $level): array
{
    $h = [
        1 => [
            'A GraphQL server can describe itself. The meta-field <code>__schema</code> lists every type, every field and every argument the endpoint will accept.',
            'The starter queries only use <code>me</code> and <code>products</code>. That is what the front end needs, not what the server offers.',
            'Ask for the map first: <code>{ __schema { queryType { name } types { name } } }</code>, then narrow to the type that looks interesting with <code>__type(name: "Query") { fields { name args { name } } }</code>.',
            'One root field is documented as internal and takes a single <code>Int!</code> argument. Its return type has a <code>content</code> field.',
            '<code>{ internalMemo(id: 3) { title content } }</code>',
        ],
        2 => [
            'Turning introspection off removes the map. It does not remove the territory: the server still has to tell a client when a field name is wrong.',
            'Look at the error from the first starter query. The handler runs the unknown name through a suggestion list built from the real field names of that type.',
            'Guess in the neighbourhood of a word rather than at random. Substrings score well, so a short guess that appears inside a real name will pull it out.',
            'There is a root field about operational notes, and its type has a field about the on-call number. Try <code>{ notes }</code>, then use what comes back and try a short guess inside the returned type.',
            '<code>{ notes }</code> names <code>staffNotes</code>; <code>{ staffNotes { pin } }</code> names <code>onCallPin</code>; then <code>{ staffNotes { area onCallPin } }</code>.',
        ],
        3 => [
            'Authorisation in GraphQL happens in resolvers, and only in resolvers. Nothing in the query language, the schema or the validator will do it for you.',
            'Read <code>Query.user</code> in the panel on the left. It takes an id, selects the row, and returns it. The session id appears nowhere in that function.',
            'This is IDOR with a different transport. The classic version is <code>GET /api/users/3</code>; here the object reference is an argument instead of a path segment.',
            'You are user #2. Ask for a different id and select the field that is documented as owner-only.',
            '<code>{ user(id: 3) { username privateNote } }</code>',
        ],
        4 => [
            'Authorisation can be attached to an object or to each field. If it is attached to the object, every field resolver has to remember to honour it, and remembering is not a security control.',
            '<code>Query.user</code> now compares the id with the session and stamps <code>_authorised</code> on the row. Three field resolvers read that stamp. Read the fourth.',
            'Select fields one at a time. The response tells you exactly which resolvers refuse and which do not, because a field error nulls that field and leaves the rest of the response intact.',
            'The field added for the mobile app re-fetches its value by id from the table. Select only that field on an id that is not yours.',
            '<code>{ user(id: 1) { apiToken } }</code>',
        ],
        5 => [
            'A rate limiter counts something. Find out what. If it counts HTTP requests, then anything that raises the amount of work per request raises your throughput for free.',
            'The limiter in the panel runs once per POST, before the document is parsed. The trace prints how many operations that one request ended up performing.',
            'Aliases let the same field appear many times in one selection set: <code>a: redeem(code:"00"){…} b: redeem(code:"01"){…}</code>. Each alias is its own resolver call with its own arguments and its own key in the response.',
            'The code is two characters from 0-9 and A-F, so there are 256 of them. Build one document containing all 256 aliased calls.',
            'Use the <em>Build all 256 aliases</em> button under the editor, send it once, and read the entry whose <code>ok</code> is <code>true</code>.',
        ],
        6 => [
            'A guard is only as good as the thing it inspects. If it reads a label the client supplies, the client controls the guard.',
            'The middleware reads <code>$body["operationName"]</code> and looks it up in <code>$PROTECTED</code>. The executor, further down, runs the operation in the <em>document</em>, whatever the body said.',
            'Two ways to end up with nothing in that lookup: leave <code>operationName</code> out of the request entirely, or send a document whose operation carries a different name.',
            'A mutation document does not need a name at all. <code>mutation { … }</code> is a complete, legal operation.',
            'Leave the operation-name box empty and send <code>mutation { promoteUser(id: 5, role: "admin") { username role } }</code>.',
        ],
        7 => [
            'Batching lets a client send several operations in one HTTP request, as a JSON array. Every element is executed; the response is an array of envelopes.',
            'Read the guard: it json-decodes the body, takes <code>$body[0]</code>, and scans that one element for a protected root field. Index 1 onwards is never looked at.',
            'Keep element 0 boring. Anything the guard is happy with will do, and a query it already permits is the least conspicuous.',
            'The array shape is <code>[{"query":"…"},{"query":"…"}]</code>. Put the protected field in the second element.',
            '<code>[{"query":"{ me { username } }"},{"query":"{ auditLog { actor entry } }"}]</code>',
        ],
        8 => [
            'Depth limiting is static analysis: it reads the document and decides before anything runs. Its accuracy depends on it modelling exactly what the executor will do.',
            'The counter in the panel walks the operation AST. When it meets a fragment spread it adds 1 and stops, because a spread has no selection set of its own. Expansion happens later.',
            'Move the deep part of your query into named fragments. Each spread hides one level plus everything below it from the counter.',
            'The value is four hops above you: <code>me -> manager -> manager -> safe -> combination</code>. Write it as a chain of fragments so the operation body stays shallow.',
            '<code>{ me { manager { ...A } } } fragment A on Employee { manager { ...B } } fragment B on Employee { safe { label combination } }</code>',
        ],
        9 => [
            'A GraphQL type says what a value looks like, not what it means. <code>String!</code> guarantees the argument is a present string. It says nothing about apostrophes.',
            '<code>Query.searchDocuments</code> pastes the filter between two single quotes to build a <code>LIKE</code> pattern. The trace prints the finished statement.',
            'Send one apostrophe first and read the SQLite error in the trace. That single request tells you whether the quote reaches the parser.',
            'The SELECT has three columns. A UNION has to match that, and the interesting column is the one the schema does not expose at all.',
            '<code>{ searchDocuments(filter: "x\' UNION SELECT id, secret_note, body FROM documents-- ") { id title } }</code>',
        ],
        10 => [
            'Chains are made of small, individually unremarkable findings. Discovery gives you a name, a guard bypass gives you the call, and the call gives you the role that a real check will honour.',
            'This endpoint answers introspection, and it also suggests field names on errors. Either one will give you the mutation field and its argument names.',
            '<code>{ __type(name: "Mutation") { fields { name args { name } } } }</code> is the shortest route. Then look at the guard in the panel and note what it inspects.',
            'Escalate first, read second. <code>adminSettings</code> reads your role from the database at request time, so the mutation has to land before the query is sent.',
            'Send <code>mutation { grantRole(userId: 4, role: "admin") { username role } }</code> with the operation-name box empty, then send <code>{ adminSettings { region vaultKey } }</code>.',
        ],
    ];
    return $h[$level] ?? [];
}

/* =========================================================================
 * Shared level UI
 * ===================================================================== */

function gq_extra_head(): string
{
    return '<style>
        .gq-ta { font-family: "JetBrains Mono", ui-monospace, monospace; font-size: 0.78rem;
                 line-height: 1.5; white-space: pre; overflow-x: auto; }
        .gq-actions { display: flex; gap: 0.6rem; flex-wrap: wrap; margin-top: 0.5rem; }
        .gq-ex { margin-bottom: 0.7rem; }
        .gq-ex-head { display: flex; align-items: center; justify-content: space-between;
                      gap: 0.6rem; margin-bottom: 0.25rem; }
        .gq-ex-head code { font-size: 0.76rem; color: var(--text-muted); }
        .gq-ex-head .btn { padding: 0.2rem 0.6rem; font-size: 0.7rem; }
        .gq-note { font-size: 0.78rem; color: var(--text-muted); margin: 0.4rem 0 0; }
        .output-box.gq-out { max-height: 340px; overflow-y: auto; word-break: normal;
                             white-space: pre-wrap; }
    </style>';
}

/**
 * The query editor every level uses: one editable document, an optional
 * operationName box, and a few read-only examples that are known to parse.
 *
 * @param array $o action, query, examples[[label,query]], operation_name (bool),
 *                 operation_name_value, label, button, extra_controls, note
 */
function gq_editor(array $o): string
{
    $action   = (string)($o['action'] ?? '');
    $query    = (string)($o['query'] ?? '');
    $label    = (string)($o['label'] ?? 'POST /graphql &mdash; query document');
    $button   = (string)($o['button'] ?? 'Send query');
    $rows     = (int)($o['rows'] ?? 9);

    ob_start(); ?>
    <form method="post" action="<?= lk_esc($action) ?>" class="gq-form">
        <div class="form-group">
            <label class="form-label"><?= $label ?></label>
            <textarea id="gq-editor" name="query" class="form-control gq-ta" rows="<?= $rows ?>"
                      spellcheck="false" autocomplete="off"><?= lk_esc($query) ?></textarea>
        </div>
        <?php if (!empty($o['operation_name'])): ?>
        <div class="form-group">
            <label class="form-label">operationName sent alongside the document (optional)</label>
            <input type="text" name="operationName" class="form-control" autocomplete="off"
                   placeholder="leave empty to send no operationName at all"
                   value="<?= lk_esc((string)($o['operation_name_value'] ?? '')) ?>">
        </div>
        <?php endif; ?>
        <?= $o['extra_controls'] ?? '' ?>
        <div class="gq-actions">
            <button class="btn btn-primary" type="submit"><?= lk_esc($button) ?></button>
            <?php if (!empty($o['reset'])): ?>
            <button class="btn btn-outline" type="submit" name="_reset" value="1">Reset lab state</button>
            <?php endif; ?>
        </div>
        <?php if (!empty($o['note'])): ?><p class="gq-note"><?= $o['note'] ?></p><?php endif; ?>
    </form>

    <?php if (!empty($o['examples'])): ?>
    <div class="lk-box"><h4><span class="lk-tag">STARTER QUERIES</span>Syntax that already parses</h4>
    <div class="lk-body">
        <p class="lk-hintline">These are here so the level is about the vulnerability and not about the grammar.
        Load one, then change it.</p>
        <?php foreach ($o['examples'] as $ex): ?>
        <div class="gq-ex">
            <div class="gq-ex-head">
                <code><?= lk_esc($ex['label']) ?></code>
                <button type="button" class="btn btn-outline gq-load">load into editor</button>
            </div>
            <textarea class="form-control gq-ta gq-ex-src" rows="<?= max(2, min(8, substr_count($ex['query'], "\n") + 1)) ?>"
                      readonly onclick="this.select()"><?= lk_esc($ex['query']) ?></textarea>
        </div>
        <?php endforeach; ?>
    </div></div>
    <?php endif;

    return ob_get_clean();
}

/** The script that wires "load into editor". Rendered once, in extra_body. */
function gq_editor_script(): string
{
    return '<script>
    document.addEventListener("click", function (e) {
        if (!e.target.classList.contains("gq-load")) return;
        var box = e.target.closest(".gq-ex").querySelector(".gq-ex-src");
        var ed  = document.getElementById("gq-editor");
        if (!box || !ed) return;
        ed.value = box.value;
        ed.focus();
        window.scrollTo({ top: ed.getBoundingClientRect().top + window.scrollY - 140, behavior: "smooth" });
    });
    </script>';
}

/** The raw envelope, exactly as a client would receive it. */
function gq_response_box(string $json, string $title = 'Raw JSON response'): string
{
    return '<div class="lk-box"><h4><span class="lk-tag">RESPONSE</span>' . lk_esc($title) . '</h4>'
         . '<div class="lk-body"><div class="output-box gq-out">' . lk_esc($json) . '</div></div></div>';
}

/** Turn engine trace events into lk_pipeline stages, after any guard stages. */
function gq_stages(array $before, ?GqlTrace $trace = null, array $after = []): array
{
    $events = $trace ? $trace->events : [];
    return array_merge($before, $events, $after);
}

/** Small "who you are on this level" banner. */
function gq_identity(string $html): string
{
    return '<div class="message info">' . $html . '</div>';
}
