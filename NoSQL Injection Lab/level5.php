<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/mongo.php';

$levelId    = 5;
$levelTitle = '$in / $or Operator Injection';
$prevLevel  = 4;
$nextLevel  = 6;

// ── Challenge logic ──────────────────────────────────────────
$users = nosql_get_users();

$raw = $_POST['query'] ?? '';
[$body, $jsonErr] = nosql_json($raw);

$query   = null;
$results = [];
$flag    = '';

if ($body !== null) {
    // VULNERABLE: the ENTIRE decoded body is used as the search filter,
    // so top-level operators like $or (and field operators like $in) are honoured.
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
    <title>Level 5 — <?= htmlspecialchars($levelTitle) ?> | NoSQL Injection Lab</title>
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
        <span class="level-badge">Level 5</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level5.php — user directory search</span>
<span class="php-variable">$users</span>  = <span class="php-function">nosql_get_users</span>();
<span class="php-variable">$filter</span> = <span class="php-function">json_decode</span>(<span class="php-variable">$_POST</span>[<span class="php-string">'query'</span>], <span class="php-keyword">true</span>);

<span class="php-comment">// VULNERABLE: the whole client filter is passed straight to find()</span>
<span class="vuln-line"><span class="php-variable">$rows</span> = <span class="php-function">mongo_find</span>(<span class="php-variable">$users</span>, <span class="php-variable">$filter</span>);</span>

<span class="php-keyword">foreach</span> (<span class="php-variable">$rows</span> <span class="php-keyword">as</span> <span class="php-variable">$u</span>) <span class="php-function">render_row</span>(<span class="php-variable">$u</span>);
<span class="php-keyword">if</span> (<span class="php-function">nosql_has_admin</span>(<span class="php-variable">$rows</span>)) <span class="php-function">award_flag</span>();<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The entire JSON filter is attacker-controlled, so you can
                inject <em>top-level</em> operators. <code>$in</code> widens a field to a list of values and
                <code>$or</code> combines whole sub-queries — either can pull the <code>admin</code> document
                into a search meant to return only ordinary users.
            </div>
        </div>

        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>This endpoint searches the user directory. The UI normally sends a filter such as
                <code>{"role":"user"}</code>, which excludes administrators.</p>
                <p>Craft a filter that widens the result set so the <code>admin</code> account appears.</p>
            </div>

            <form method="post" action="level5.php">
                <div class="form-group">
                    <label class="form-label" for="query_input">Search filter (JSON)</label>
                    <textarea id="query_input" name="query" class="form-control" rows="4" spellcheck="false"
                        placeholder='{"role":{"$in":["user","admin"]}}'><?= htmlspecialchars($raw) ?></textarea>
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Search</button>
                    <?php if ($raw !== ''): ?>
                    <a href="level5.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($jsonErr !== ''): ?>
            <div class="message error"><?= htmlspecialchars($jsonErr) ?></div>
            <?php endif; ?>

            <?php if ($query !== null): ?>
            <div class="query-echo"><span class="k">db.users.find(</span><?= htmlspecialchars(nosql_query_repr($query)) ?><span class="k">)</span></div>

                <?php if (!empty($results)): ?>
                    <div class="result-box">Search returned <?= count($results) ?> document(s).</div>
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
                    <div class="oracle nomatch">&#x2717; No documents matched your filter.</div>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; Admin document exposed!</h3>
                <p>Your widened filter pulled the admin account into the results.</p>
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
