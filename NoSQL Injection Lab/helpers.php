<?php
/**
 * NoSQL Injection Lab — Helper Functions
 * Flags, progressive hints, hint renderer, and the inline / central flag-submit logic.
 * Mirrors the XSS Lab helper set (cookie name changed to nosql_lab_progress).
 */

/**
 * Returns the flag string for a given level ID.
 */
function get_flag_for_level(int $levelId): string
{
    $flags = [
        1  => 'FLAG{nosql_ne_bypass}',
        2  => 'FLAG{nosql_array_operator}',
        3  => 'FLAG{nosql_gt_bypass}',
        4  => 'FLAG{nosql_regex_extraction}',
        5  => 'FLAG{nosql_operator_injection}',
        6  => 'FLAG{nosql_where_injection}',
        7  => 'FLAG{nosql_blind_boolean}',
        8  => 'FLAG{nosql_dollar_filter_bypass}',
        9  => 'FLAG{nosql_type_confusion}',
        10 => 'FLAG{nosql_waf_bypass}',
    ];
    return $flags[$levelId] ?? '';
}

/**
 * Returns an array of 5 progressive hints for each level
 * (conceptual → … → full working payload).
 */
function get_level_hints(int $levelId): array
{
    $hints = [
        1 => [
            'This is a JSON login endpoint. The server decodes your request body and passes it <strong>straight into</strong> <code>db.users.find()</code>. Whatever shape your JSON has becomes the query shape.',
            'The developer expects <code>password</code> to be a <em>string</em> to compare against. But in MongoDB, a field value can also be an <strong>operator object</strong> like <code>{"$gt": 1}</code> or <code>{"$ne": null}</code>.',
            'The admin password is a long random secret you can never guess. Instead of matching it, ask for "any password that is <strong>not equal to null</strong>" — every real user (including admin) has a non-null password.',
            'Keep <code>username</code> as the literal string <code>admin</code>, and replace the <em>password string</em> with an operator object.',
            'Working payload (request body): <code>{"username":"admin","password":{"$ne":null}}</code>',
        ],
        2 => [
            'This login uses the <strong>URL query string</strong>, not JSON. But PHP has a quirk: <code>?password[$ne]=x</code> is parsed by PHP into the array <code>["$ne" =&gt; "x"]</code> — an operator object appears with no JSON at all.',
            'Look at how the query is built: <code>$_GET[\'password\']</code> is dropped straight into the Mongo filter. If that value is an array, the operator goes with it.',
            'You cannot type <code>[</code> and <code>]</code> into a normal form field easily, so edit the URL directly in the address bar.',
            'Set the username to <code>admin</code> and turn the password into a <code>$ne</code> operator via bracket syntax.',
            'Working payload (URL): <code>?username=admin&amp;password[$ne]=x</code>',
        ],
        3 => [
            'Same JSON login as Level 1 — but a filter now runs on your raw body first. Read the <span class="mono">vulnerable source</span>: which exact substring does it reject?',
            'The blacklist blocks <code>$ne</code>. That kills the Level 1 payload. But <code>$ne</code> is only <em>one</em> of MongoDB\'s comparison operators.',
            'You need a different operator that still matches the admin\'s unknown (but non-empty) password. Think about <strong>greater-than</strong>.',
            'Any real password string is <code>&gt; ""</code> (greater than the empty string). Use <code>$gt</code> with an empty-string operand.',
            'Working payload (request body): <code>{"username":"admin","password":{"$gt":""}}</code>',
        ],
        4 => [
            'The admin\'s password is <strong>secret</strong> and the page never prints it — it only tells you whether <em>a</em> user matched. Your job is to <strong>extract</strong> the secret one character at a time.',
            'MongoDB\'s <code>$regex</code> operator lets you test a field against a pattern. <code>{"password":{"$regex":"^F"}}</code> is true only if the admin password <em>starts with</em> <code>F</code>.',
            'Binary-search / brute-force each position: try <code>^F</code>, then <code>^FL</code>, <code>^FLA</code>, … keeping every character that returns "a user matched".',
            'The secret is itself a <code>FLAG{...}</code> value. Write the braces <em>literally</em> in the regex — <code>{</code> and <code>}</code> are ordinary characters here, and a backslash escape like <code>\\{</code> would be rejected as invalid JSON.',
            'When you have every character, confirm with a fully-anchored <code>^...$</code> pattern to capture the flag: <code>{"username":"admin","password":{"$regex":"^FLAG{nosql_regex_extraction}$"}}</code>',
        ],
        5 => [
            'This is a document <strong>search</strong> endpoint: your entire JSON body becomes the filter passed to <code>db.users.find()</code>. That means you can inject <em>top-level</em> operators, not just field values.',
            'The interface is meant to search ordinary users. You want the <code>admin</code> document included in the results.',
            'The <code>$in</code> operator matches when a field equals any value in a list: <code>{"role":{"$in":["user","admin"]}}</code> widens the search to include admins.',
            'Alternatively the <code>$or</code> operator combines whole sub-queries: <code>{"$or":[ {"role":"admin"}, {"role":"user"} ]}</code>.',
            'Working payloads: <code>{"role":{"$in":["user","admin"]}}</code> &nbsp;|&nbsp; <code>{"$or":[{"username":"admin"},{"username":"nobody"}]}</code>',
        ],
        6 => [
            'This filter supports MongoDB\'s <code>$where</code> operator, which evaluates a <strong>JavaScript predicate</strong> against every document. Your input becomes that predicate.',
            'Because the whole predicate string is attacker-controlled, you can supply an expression that is <strong>always true</strong>, matching every document — admin included.',
            'The classic tautology is <code>1==1</code>. As a Mongo query: <code>{"$where":"1==1"}</code>.',
            'You can also target admin precisely by reading document fields via <code>this</code>: <code>this.role=="admin"</code>.',
            'Working payloads: <code>{"$where":"1==1"}</code> &nbsp;|&nbsp; <code>{"$where":"this.role==\'admin\'"}</code>',
        ],
        7 => [
            'Purely <strong>blind</strong> boolean oracle: the response is only ever "Login successful" or "Login failed". No counts, no data — just one bit. And every operator except <code>$regex</code> is rejected, so you cannot simply bypass auth.',
            'That single bit is enough. <code>{"password":{"$regex":"^F"}}</code> flips the bit when the admin secret starts with <code>F</code>. Iterate to reconstruct it character by character.',
            'For each position, try every candidate character and keep the one that returns "Login successful". The secret is a <code>FLAG{...}</code> value.',
            'Write the braces literally (a <code>\\{</code> escape would be invalid JSON) and always keep <code>username</code> as <code>admin</code> so only the admin document is tested.',
            'Capture it with the fully-anchored <code>^...$</code> pattern: <code>{"username":"admin","password":{"$regex":"^FLAG{nosql_blind_boolean}$"}}</code>',
        ],
        8 => [
            'A WAF now inspects your <strong>raw request body</strong> and rejects it if it contains a literal <code>$</code> character. So <code>{"$ne":null}</code> is blocked before it is ever decoded.',
            'The filter checks the bytes <em>before</em> <code>json_decode()</code>. JSON, however, lets you write any character in a string using a <code>\\uXXXX</code> escape.',
            'The dollar sign <code>$</code> is Unicode code point U+0024. In a JSON key you can write it as <code>\\u0024</code> — no literal <code>$</code> byte appears in the raw body.',
            '<code>json_decode()</code> turns <code>"\\u0024ne"</code> back into the real key <code>$ne</code>, which the Mongo evaluator then honours.',
            'Working payload (request body): <code>{"username":"admin","password":{"\\u0024ne":null}}</code>',
        ],
        9 => [
            'The server tries to block admin logins with a strict check: <code>if ($username === "admin") { deny(); }</code>. Yet the Mongo query is still built from your raw input.',
            'A PHP <code>===</code> comparison is <strong>type-sensitive</strong>. An <em>array</em> is never <code>===</code> to the string <code>"admin"</code>, so an array-valued username slips past the guard.',
            'But <code>{"$eq":"admin"}</code> as the username still matches the admin document inside Mongo. The guard sees an array; the database sees "equals admin".',
            'Deliver the array via PHP query-string bracket syntax on <code>username</code>, and bypass the password with an operator too.',
            'Working payload (URL): <code>?username[$eq]=admin&amp;password[$ne]=x</code>',
        ],
        10 => [
            'Three stacked filters. Layer 1 rejects a literal <code>$</code> in the raw body. Layer 2 rejects the username field unless it is a plain string. Layer 3 blacklists the operators <code>$ne, $regex, $where, $in, $or, $nin</code> after decoding.',
            'Layer 1 is the Level 8 problem — defeat it with a <code>\\u0024</code> unicode escape so no literal <code>$</code> byte appears.',
            'Layer 2 means you must keep <code>username</code> as the literal string <code>"admin"</code> and smuggle the operator through the <code>password</code> field instead.',
            'Layer 3 blacklists six operators — but not all of them. Which comparison operator survives? The one that matches "any non-empty password" is <code>$gt</code>.',
            'Working payload (request body): <code>{"username":"admin","password":{"\\u0024gt":""}}</code>',
        ],
    ];
    return $hints[$levelId] ?? [];
}

/**
 * Renders a progressive hint section with a "Show Next Hint" button.
 * Each call shares the same JS listener (rendered only once via static flag).
 */
function render_hint_section(array $hints, string $title = 'Hints'): string
{
    if (empty($hints)) return '';
    static $scriptRendered = false;
    $id = uniqid('hint_', false);
    ob_start();
    ?>
    <div class="hints" id="<?= $id ?>">
        <h3><?= htmlspecialchars($title) ?></h3>
        <button class="hint-btn" data-hint-target="<?= $id ?>">Show Next Hint (0/<?= count($hints) ?>)</button>
        <ul class="hint-list">
            <?php foreach ($hints as $hint): ?>
            <li class="hint-item" hidden><?= $hint ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
    <?php
    if (!$scriptRendered) {
        $scriptRendered = true;
        ?>
        <script>
        document.addEventListener('click', function(e) {
            if (!e.target.classList.contains('hint-btn')) return;
            const targetId = e.target.getAttribute('data-hint-target');
            const container = document.getElementById(targetId);
            const items = container.querySelectorAll('.hint-item[hidden]');
            const total = container.querySelectorAll('.hint-item').length;
            if (items.length > 0) {
                items[0].removeAttribute('hidden');
                const shown = total - items.length + 1;
                e.target.textContent = shown < total ? 'Show Next Hint (' + shown + '/' + total + ')' : 'All hints shown';
                if (shown >= total) e.target.disabled = true;
            }
        });
        </script>
        <?php
    }
    return ob_get_clean();
}

/**
 * Handle inline flag submission on a level page.
 * Only acts when POST contains _flag_submit=1.
 *
 * @return array{status: string|null, message: string, already_completed: bool}
 */
function handle_inline_flag_submit(int $levelId): array
{
    $result = ['status' => null, 'message' => '', 'already_completed' => false];

    $completed = [];
    if (!empty($_COOKIE['nosql_lab_progress'])) {
        $decoded = json_decode($_COOKIE['nosql_lab_progress'], true);
        if (is_array($decoded)) $completed = $decoded;
    }
    $result['already_completed'] = in_array($levelId, $completed);

    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['_flag_submit'])) {
        return $result;
    }

    $flag = trim($_POST['submitted_flag'] ?? '');
    if ($flag === '') {
        $result['status']  = 'error';
        $result['message'] = 'Please enter a flag.';
        return $result;
    }

    if ($flag === get_flag_for_level($levelId)) {
        if (!in_array($levelId, $completed)) {
            $completed[] = $levelId;
            sort($completed);
            setcookie('nosql_lab_progress', json_encode($completed), time() + 86400 * 30, '/');
        }
        $result['status']            = 'success';
        $result['message']           = 'Correct! Flag accepted.';
        $result['already_completed'] = true;
    } else {
        $result['status']  = 'error';
        $result['message'] = 'Incorrect flag. Keep trying!';
    }

    return $result;
}

/**
 * Render the compact inline flag submit form.
 *
 * @param array{status: string|null, message: string, already_completed: bool} $result
 */
function render_inline_flag_form(int $levelId, array $result): string
{
    $status           = $result['status'] ?? null;
    $message          = $result['message'] ?? '';
    $alreadyCompleted = $result['already_completed'] ?? false;

    ob_start();
    ?>
    <div class="inline-flag-submit">
        <h3>Submit Flag</h3>
        <div class="form-inner">
            <?php if ($status === 'success'): ?>
                <div class="message success"><?= htmlspecialchars($message) ?> &mdash; <a href="submit.php">view all progress &rarr;</a></div>
            <?php elseif ($status === 'error'): ?>
                <div class="message error"><?= htmlspecialchars($message) ?></div>
            <?php endif; ?>
            <?php if ($alreadyCompleted && $status !== 'success'): ?>
                <div class="message info">Level <?= (int)$levelId ?> already completed. <a href="submit.php">View progress &rarr;</a></div>
            <?php endif; ?>
            <?php if (!$alreadyCompleted || $status === 'error'): ?>
            <form method="POST" action="">
                <input type="hidden" name="_flag_submit" value="1">
                <div class="inline-flag-row">
                    <input type="text" name="submitted_flag" class="form-control"
                           placeholder="FLAG{...}" autocomplete="off" spellcheck="false"
                           value="<?= htmlspecialchars($_POST['submitted_flag'] ?? '') ?>">
                    <button type="submit" class="btn btn-primary">Check</button>
                </div>
            </form>
            <?php endif; ?>
        </div>
    </div>
    <?php
    return ob_get_clean();
}
