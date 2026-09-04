<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/mongo.php';

$levelId    = 10;
$levelTitle = 'Multi-Layer WAF Bypass';
$prevLevel  = 9;
$nextLevel  = 0;

// ── Challenge logic ──────────────────────────────────────────
$users = nosql_get_users();

$raw = $_POST['query'] ?? '';

$blockedMsg = '';
$query      = null;
$results    = [];
$flag       = '';
$jsonErr    = '';

if ($raw !== '') {
    // Layer 1: reject any literal "$" in the raw body.
    if (strpos($raw, '$') !== false) {
        $blockedMsg = 'Layer 1 blocked the request: a literal "$" was found in the raw body.';
    } else {
        [$body, $jsonErr] = nosql_json($raw);
        if ($body !== null) {
            // Layer 2: the username field must be a plain string (no operator objects there).
            if (isset($body['username']) && !is_string($body['username'])) {
                $blockedMsg = 'Layer 2 blocked the request: the username field must be a plain string.';
            } else {
                // Layer 3: blacklist a set of operators (but not all of them).
                $blacklist = ['$ne', '$regex', '$where', '$in', '$or', '$nin'];
                $bad = '';
                foreach (nosql_operators_used($body) as $op) {
                    if (in_array($op, $blacklist, true)) { $bad = $op; break; }
                }
                if ($bad !== '') {
                    $blockedMsg = 'Layer 3 blocked the request: operator ' . $bad . ' is blacklisted.';
                } else {
                    // VULNERABLE: whatever survives all three layers builds the query unsanitized.
                    $query = [
                        'username' => $body['username'] ?? '',
                        'password' => $body['password'] ?? '',
                    ];
                    $results = mongo_find($users, $query);
                    if (nosql_has_admin($results)) {
                        $flag = get_flag_for_level($levelId);
                    }
                }
            }
        }
    }
}

$hints        = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 10 — <?= htmlspecialchars($levelTitle) ?> | NoSQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>

<header class="header">
    <a href="index.php" class="back-btn">&larr; Back to Levels</a>
    <div class="header-title"><span>&#x1F4E6;</span> NoSQL Injection Lab</div>
    <a href="submit.php" class="submit-link">Submit Flag</a>
</header>

<div class="container">

    <div class="level-header">
        <span class="level-badge">Level 10</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-expert">Expert</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level10.php — three stacked WAF layers</span>
<span class="php-variable">$raw</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'query'</span>];

<span class="php-comment">// L1: no literal "$"   L2: username must be string   L3: operator blacklist</span>
<span class="php-keyword">if</span> (<span class="php-function">strpos</span>(<span class="php-variable">$raw</span>, <span class="php-string">'$'</span>) !== <span class="php-keyword">false</span>) <span class="php-function">reject</span>();
<span class="php-variable">$b</span> = <span class="php-function">json_decode</span>(<span class="php-variable">$raw</span>, <span class="php-keyword">true</span>);
<span class="php-keyword">if</span> (!<span class="php-function">is_string</span>(<span class="php-variable">$b</span>[<span class="php-string">'username'</span>])) <span class="php-function">reject</span>();
<span class="php-keyword">foreach</span> ([<span class="php-string">'$ne'</span>,<span class="php-string">'$regex'</span>,<span class="php-string">'$where'</span>,<span class="php-string">'$in'</span>,<span class="php-string">'$or'</span>,<span class="php-string">'$nin'</span>] <span class="php-keyword">as</span> <span class="php-variable">$op</span>)
    <span class="php-keyword">if</span> (<span class="php-function">uses_op</span>(<span class="php-variable">$b</span>, <span class="php-variable">$op</span>)) <span class="php-function">reject</span>();

<span class="vuln-line"><span class="php-variable">$query</span> = [<span class="php-string">'username'</span> =&gt; <span class="php-variable">$b</span>[<span class="php-string">'username'</span>], <span class="php-string">'password'</span> =&gt; <span class="php-variable">$b</span>[<span class="php-string">'password'</span>]];</span>
<span class="php-keyword">if</span> (<span class="php-function">nosql_has_admin</span>(<span class="php-function">mongo_find</span>(<span class="php-variable">$users</span>, <span class="php-variable">$query</span>))) <span class="php-function">award_flag</span>();<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; Each layer plugs one hole from an earlier level — literal
                <code>$</code> (L8), operator objects on username (L9), and six named operators. But the
                blacklist is not exhaustive: <code>$gt</code> is missing. Encode it as <code>\u0024gt</code> to
                beat L1, keep <code>username</code> a string to beat L2, and it sails through L3.
            </div>
        </div>

        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>The final endpoint stacks three defences at once. Every trick from the earlier levels is
                individually blocked — but exactly one operator survives all three layers.</p>
                <p>Combine the unicode-escape bypass with the surviving operator to log in as admin.</p>
            </div>

            <form method="post" action="level10.php">
                <div class="form-group">
                    <label class="form-label" for="query_input">Login request body (JSON)</label>
                    <textarea id="query_input" name="query" class="form-control" rows="4" spellcheck="false"
                        placeholder='{"username":"admin","password":{ ... }}'><?= htmlspecialchars($raw) ?></textarea>
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Send Login</button>
                    <?php if ($raw !== ''): ?>
                    <a href="level10.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($blockedMsg !== ''): ?>
            <div class="message error">&#x1F6AB; <?= htmlspecialchars($blockedMsg) ?></div>
            <?php endif; ?>

            <?php if ($jsonErr !== ''): ?>
            <div class="message error"><?= htmlspecialchars($jsonErr) ?></div>
            <?php endif; ?>

            <?php if ($query !== null): ?>
            <div class="query-echo"><span class="k">db.users.find(</span><?= htmlspecialchars(nosql_query_repr($query)) ?><span class="k">)</span></div>

                <?php if (!empty($results)): ?>
                    <div class="oracle match">&#x2714; Login successful — matched <?= count($results) ?> document(s)</div>
                    <table class="data-table">
                        <tr><th>username</th><th>role</th><th>email</th></tr>
                        <?php foreach ($results as $r): ?>
                        <tr>
                            <td><?= htmlspecialchars((string)($r['username'] ?? '')) ?></td>
                            <td><?= htmlspecialchars((string)($r['role'] ?? '')) ?></td>
                            <td><?= htmlspecialchars((string)($r['email'] ?? '')) ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </table>
                <?php else: ?>
                    <div class="oracle nomatch">&#x2717; Login failed — no document matched</div>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; All three layers defeated!</h3>
                <p>The surviving operator, unicode-encoded, matched the admin document.</p>
                <code><?= htmlspecialchars($flag) ?></code>
                <p style="margin-top:0.75rem; font-size:0.8rem;">
                    <a href="submit.php">Submit this flag &rarr;</a>
                </p>
            </div>
            <?php endif; ?>

        </div><!-- /.challenge-panel -->
    </div><!-- /.challenge-layout -->

    <?= render_hint_section($hints) ?>
    <?= render_inline_flag_form($levelId, $_flag_result) ?>

    <div class="navigation">
        <a href="index.php" class="btn btn-secondary">&larr; Home</a>
        <a href="level<?= $prevLevel ?>.php" class="btn btn-secondary">&larr; Level <?= $prevLevel ?></a>
        <a href="submit.php" class="next-link">Finish &rarr; Submit</a>
    </div>

</div><!-- /.container -->
</body>
</html>
