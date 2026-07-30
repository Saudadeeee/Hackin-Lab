<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/mongo.php';

$levelId    = 6;
$levelTitle = '$where JavaScript Injection';
$prevLevel  = 5;
$nextLevel  = 7;

// ── Challenge logic ──────────────────────────────────────────
$users = nosql_get_users();

$raw = $_POST['query'] ?? '';
[$body, $jsonErr] = nosql_json($raw);

$query   = null;
$results = [];
$flag    = '';

if ($body !== null) {
    // VULNERABLE: the whole filter is honoured, including $where — a JavaScript
    // predicate string that is evaluated against every document.
    $query   = $body;
    $results = mongo_find($users, $query);
    if (nosql_has_admin($results)) {
        $flag = get_flag_for_level($levelId);
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
    <title>Level 6 — <?= htmlspecialchars($levelTitle) ?> | NoSQL Injection Lab</title>
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
        <span class="level-badge">Level 6</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level6.php — "advanced" filter with $where support</span>
<span class="php-variable">$users</span>  = <span class="php-function">nosql_get_users</span>();
<span class="php-variable">$filter</span> = <span class="php-function">json_decode</span>(<span class="php-variable">$_POST</span>[<span class="php-string">'query'</span>], <span class="php-keyword">true</span>);

<span class="php-comment">// VULNERABLE: $where runs an attacker-supplied JS predicate per document</span>
<span class="vuln-line"><span class="php-variable">$rows</span> = <span class="php-function">mongo_find</span>(<span class="php-variable">$users</span>, <span class="php-variable">$filter</span>);  <span class="php-comment">// e.g. {"$where":"1==1"}</span></span>

<span class="php-keyword">if</span> (<span class="php-function">nosql_has_admin</span>(<span class="php-variable">$rows</span>)) <span class="php-function">award_flag</span>();<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; MongoDB's <code>$where</code> evaluates a JavaScript
                expression against every document, with <code>this</code> bound to the row. Because your input
                becomes the whole predicate, a tautology like <code>1==1</code> matches every document, and
                <code>this.role=='admin'</code> targets the admin directly.
            </div>
        </div>

        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>This directory filter supports server-side JavaScript via <code>$where</code>. The predicate
                string you provide is executed for each user document.</p>
                <p>Supply a predicate that matches the <code>admin</code> record.</p>
            </div>

            <form method="post" action="level6.php">
                <div class="form-group">
                    <label class="form-label" for="query_input">Filter (JSON)</label>
                    <textarea id="query_input" name="query" class="form-control" rows="4" spellcheck="false"
                        placeholder='{"$where":"1==1"}'><?= htmlspecialchars($raw) ?></textarea>
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Run Filter</button>
                    <?php if ($raw !== ''): ?>
                    <a href="level6.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($jsonErr !== ''): ?>
            <div class="message error"><?= htmlspecialchars($jsonErr) ?></div>
            <?php endif; ?>

            <?php if ($query !== null): ?>
            <div class="query-echo"><span class="k">db.users.find(</span><?= htmlspecialchars(nosql_query_repr($query)) ?><span class="k">)</span></div>

                <?php if (!empty($results)): ?>
                    <div class="result-box">Predicate matched <?= count($results) ?> document(s).</div>
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
                    <div class="oracle nomatch">&#x2717; The predicate matched no documents.</div>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; Predicate bypass!</h3>
                <p>Your JavaScript predicate matched the admin document.</p>
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
        <a href="level<?= $nextLevel ?>.php" class="next-link">Level <?= $nextLevel ?> &rarr;</a>
    </div>

</div><!-- /.container -->
</body>
</html>
