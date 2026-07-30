<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/mongo.php';

$levelId    = 1;
$levelTitle = 'Auth Bypass via $ne';
$prevLevel  = 0;
$nextLevel  = 2;

// ── Challenge logic ──────────────────────────────────────────
$users = nosql_get_users();

$raw = $_POST['query'] ?? '';
[$body, $jsonErr] = nosql_json($raw);

$query   = null;
$results = [];
$flag    = '';

if ($body !== null) {
    // VULNERABLE: the decoded JSON is used to build the query with no type checking.
    // A password value of {"$ne": null} becomes a Mongo operator object.
    $query = [
        'username' => $body['username'] ?? '',
        'password' => $body['password'] ?? '',
    ];
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
    <title>Level 1 — <?= htmlspecialchars($levelTitle) ?> | NoSQL Injection Lab</title>
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
        <span class="level-badge">Level 1</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-easy">Easy</span>
    </div>

    <div class="challenge-layout">

        <!-- ── Left: Source Code Panel ── -->
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level1.php — JSON login endpoint (no real MongoDB; simulated)</span>
<span class="php-variable">$users</span> = <span class="php-function">nosql_get_users</span>();
<span class="php-variable">$body</span>  = <span class="php-function">json_decode</span>(<span class="php-variable">$_POST</span>[<span class="php-string">'query'</span>], <span class="php-keyword">true</span>);

<span class="php-comment">// VULNERABLE: user JSON builds the query with no type checking</span>
<span class="vuln-line"><span class="php-variable">$query</span> = [</span>
<span class="vuln-line">    <span class="php-string">'username'</span> =&gt; <span class="php-variable">$body</span>[<span class="php-string">'username'</span>] ?? <span class="php-string">''</span>,</span>
<span class="vuln-line">    <span class="php-string">'password'</span> =&gt; <span class="php-variable">$body</span>[<span class="php-string">'password'</span>] ?? <span class="php-string">''</span>,  <span class="php-comment">// may be {"$ne": null}</span></span>
<span class="vuln-line">];</span>
<span class="php-variable">$user</span> = <span class="php-function">mongo_find</span>(<span class="php-variable">$users</span>, <span class="php-variable">$query</span>);
<span class="php-keyword">if</span> (<span class="php-function">nosql_has_admin</span>(<span class="php-variable">$user</span>)) <span class="php-function">award_flag</span>();<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The <code>password</code> field is taken verbatim from the
                decoded JSON. The developer assumed it would be a string to compare, but MongoDB treats an
                object like <code>{"$ne": null}</code> as a <em>query operator</em> — "not equal to null" —
                which every real account (including <code>admin</code>) satisfies.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>A single-page app logs in by POSTing a JSON body <code>{"username":"...","password":"..."}</code>
                to this endpoint. You do <strong>not</strong> know the admin password — it is a long random secret.</p>
                <p>Edit the JSON below so the query matches the <code>admin</code> document anyway, then submit.</p>
            </div>

            <form method="post" action="level1.php">
                <div class="form-group">
                    <label class="form-label" for="query_input">Login request body (JSON)</label>
                    <textarea
                        id="query_input"
                        name="query"
                        class="form-control"
                        rows="4"
                        spellcheck="false"
                        placeholder='{"username":"admin","password":{"$ne":null}}'
                    ><?= htmlspecialchars($raw) ?></textarea>
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Send Login</button>
                    <?php if ($raw !== ''): ?>
                    <a href="level1.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

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
                <h3>&#x1F3C6; Admin session obtained!</h3>
                <p>You authenticated as <strong>admin</strong> without knowing the password.</p>
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
        <a href="submit.php" class="btn btn-secondary nav-center">Submit Flag</a>
        <a href="level<?= $nextLevel ?>.php" class="next-link">Level <?= $nextLevel ?> &rarr;</a>
    </div>

</div><!-- /.container -->
</body>
</html>
