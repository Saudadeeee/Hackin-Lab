<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/mongo.php';

$levelId    = 9;
$levelTitle = 'Type-Confusion === Bypass';
$prevLevel  = 8;
$nextLevel  = 10;

// ── Challenge logic ──────────────────────────────────────────
$users = nosql_get_users();

$submitted = isset($_GET['username']) || isset($_GET['password']);
$username  = $_GET['username'] ?? '';
$password  = $_GET['password'] ?? '';

$denied  = false;
$query   = null;
$results = [];
$flag    = '';

if ($submitted) {
    // Guard: forbid admin logins with a strict (type-sensitive) comparison.
    if ($username === 'admin') {
        $denied = true;
    } else {
        // VULNERABLE: an array username is not === 'admin', but Mongo still matches it.
        $query   = ['username' => $username, 'password' => $password];
        $results = mongo_find($users, $query);
        if (nosql_has_admin($results)) {
            $flag = get_flag_for_level($levelId);
        }
    }
}

$uStr = is_array($username) ? json_encode($username) : (string)$username;
$pStr = is_array($password) ? json_encode($password) : (string)$password;

$hints        = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 9 — <?= htmlspecialchars($levelTitle) ?> | NoSQL Injection Lab</title>
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
        <span class="level-badge">Level 9</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-hard">Hard</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level9.php — "admin login is disabled" guard</span>
<span class="php-variable">$users</span>    = <span class="php-function">nosql_get_users</span>();
<span class="php-variable">$username</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'username'</span>] ?? <span class="php-string">''</span>;
<span class="php-variable">$password</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'password'</span>] ?? <span class="php-string">''</span>;

<span class="php-comment">// Guard meant to block admin — but === is type-sensitive</span>
<span class="vuln-line"><span class="php-keyword">if</span> (<span class="php-variable">$username</span> === <span class="php-string">'admin'</span>) <span class="php-function">deny</span>();  <span class="php-comment">// array !== string 'admin'</span></span>

<span class="php-variable">$query</span> = [<span class="php-string">'username'</span> =&gt; <span class="php-variable">$username</span>, <span class="php-string">'password'</span> =&gt; <span class="php-variable">$password</span>];
<span class="php-keyword">if</span> (<span class="php-function">nosql_has_admin</span>(<span class="php-function">mongo_find</span>(<span class="php-variable">$users</span>, <span class="php-variable">$query</span>))) <span class="php-function">award_flag</span>();<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The guard uses PHP's strict <code>===</code>, which is
                type-sensitive: an <em>array</em> is never identical to the string <code>'admin'</code>. Send
                <code>username[$eq]=admin</code> and the guard sees an array (skips the deny), while MongoDB
                evaluates <code>{"username":{"$eq":"admin"}}</code> and matches the admin document.
            </div>
        </div>

        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>Admin login has been "disabled" by a check that rejects the username <code>admin</code>. The
                query is still built from your raw GET parameters.</p>
                <p>Slip an array past the strict string comparison, then match admin in the database.</p>
            </div>

            <form method="get" action="level9.php">
                <div class="form-group">
                    <label class="form-label" for="u">username</label>
                    <input type="text" id="u" name="username" class="form-control"
                           value="<?= htmlspecialchars($uStr) ?>" autocomplete="off" spellcheck="false" placeholder="admin">
                </div>
                <div class="form-group" style="margin-top:0.6rem;">
                    <label class="form-label" for="p">password</label>
                    <input type="text" id="p" name="password" class="form-control"
                           value="<?= htmlspecialchars($pStr) ?>" autocomplete="off" spellcheck="false" placeholder="password">
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Log In</button>
                    <a href="level9.php?username%5B%24eq%5D=admin&amp;password%5B%24ne%5D=x" class="btn btn-secondary">Inject username[$eq]=admin</a>
                </div>
            </form>

            <?php if ($denied): ?>
            <div class="message error">&#x1F6AB; Admin login is disabled. (The guard matched your username string.)</div>
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
                <h3>&#x1F3C6; Guard bypassed via type confusion!</h3>
                <p>An array username defeated the strict <code>===</code> check.</p>
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
