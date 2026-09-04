<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/mongo.php';

$levelId    = 8;
$levelTitle = 'Dollar-Keyword Filter Bypass';
$prevLevel  = 7;
$nextLevel  = 9;

// ── Challenge logic ──────────────────────────────────────────
$users = nosql_get_users();

$raw = $_POST['query'] ?? '';

// Obstacle: reject any raw body that contains a literal "$" byte.
$blocked = ($raw !== '' && strpos($raw, '$') !== false);

$query   = null;
$results = [];
$flag    = '';
$jsonErr = '';

if (!$blocked) {
    [$body, $jsonErr] = nosql_json($raw);
    if ($body !== null) {
        // VULNERABLE: after decoding, "$ne" is the real key "$ne" again.
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

$hints        = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 8 — <?= htmlspecialchars($levelTitle) ?> | NoSQL Injection Lab</title>
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
        <span class="level-badge">Level 8</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-hard">Hard</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level8.php — WAF strips operator keywords by their "$"</span>
<span class="php-variable">$users</span> = <span class="php-function">nosql_get_users</span>();
<span class="php-variable">$raw</span>   = <span class="php-variable">$_POST</span>[<span class="php-string">'query'</span>];

<span class="php-comment">// Defence: reject the raw body if it contains a literal "$"</span>
<span class="php-keyword">if</span> (<span class="php-function">strpos</span>(<span class="php-variable">$raw</span>, <span class="php-string">'$'</span>) !== <span class="php-keyword">false</span>) <span class="php-function">reject</span>();

<span class="php-variable">$body</span>  = <span class="php-function">json_decode</span>(<span class="php-variable">$raw</span>, <span class="php-keyword">true</span>);  <span class="php-comment">// $ne -&gt; $ne</span>
<span class="vuln-line"><span class="php-variable">$query</span> = [<span class="php-string">'username'</span> =&gt; <span class="php-variable">$body</span>[<span class="php-string">'username'</span>], <span class="php-string">'password'</span> =&gt; <span class="php-variable">$body</span>[<span class="php-string">'password'</span>]];</span>
<span class="php-keyword">if</span> (<span class="php-function">nosql_has_admin</span>(<span class="php-function">mongo_find</span>(<span class="php-variable">$users</span>, <span class="php-variable">$query</span>))) <span class="php-function">award_flag</span>();<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The filter inspects the <em>raw bytes</em> before JSON
                decoding. JSON strings allow <code>\uXXXX</code> escapes, and <code>$</code> is U+0024. Writing
                the key as <code>"\u0024ne"</code> contains no literal <code>$</code>, yet
                <code>json_decode()</code> restores it to <code>$ne</code>.
            </div>
        </div>

        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>A "NoSQL WAF" blocks any request body containing a <code>$</code> character, hoping to stop
                all operator injection. But it validates the string before it is parsed as JSON.</p>
                <p>Encode the operator key so no literal <code>$</code> appears in the body.</p>
            </div>

            <form method="post" action="level8.php">
                <div class="form-group">
                    <label class="form-label" for="query_input">Login request body (JSON)</label>
                    <textarea id="query_input" name="query" class="form-control" rows="4" spellcheck="false"
                        placeholder='{"username":"admin","password":{ ... }}'><?= htmlspecialchars($raw) ?></textarea>
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Send Login</button>
                    <?php if ($raw !== ''): ?>
                    <a href="level8.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($blocked): ?>
            <div class="message error">&#x1F6AB; Blocked by WAF: the request body contains a literal <code>$</code> character.</div>
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
                <h3>&#x1F3C6; WAF bypassed!</h3>
                <p>The unicode-escaped operator key slipped past the literal-<code>$</code> filter.</p>
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
