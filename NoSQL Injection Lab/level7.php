<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/mongo.php';

$levelId    = 7;
$levelTitle = 'Blind Boolean Extraction';
$prevLevel  = 6;
$nextLevel  = 8;

// ── Challenge logic ──────────────────────────────────────────
// The admin password IS the flag and is never printed. The only feedback is a
// single bit: login succeeded or failed. Every operator but $regex is rejected.
$users  = nosql_get_users($levelId);
$secret = get_flag_for_level($levelId);

$raw = $_POST['query'] ?? '';
[$body, $jsonErr] = nosql_json($raw);

$query     = null;
$loginOk   = false;
$flag      = '';
$blockedOp = '';
$regexUsed = '';

if ($body !== null) {
    // Obstacle: allow ONLY $regex (and its $options). Any other operator is refused.
    foreach (nosql_operators_used($body) as $op) {
        if ($op !== '$regex' && $op !== '$options') { $blockedOp = $op; break; }
    }

    if ($blockedOp === '') {
        // VULNERABLE: the $regex operator on password is still honoured.
        $query = [
            'username' => $body['username'] ?? '',
            'password' => $body['password'] ?? '',
        ];
        $results = mongo_find($users, $query);
        $loginOk = nosql_has_admin($results);

        if (isset($body['password']) && is_array($body['password']) && isset($body['password']['$regex'])) {
            $regexUsed = (string)$body['password']['$regex'];
        }
        if ($regexUsed !== '' && nosql_regex_fully_matches($regexUsed, $secret)) {
            $flag = $secret;
        } elseif (isset($body['password']) && is_string($body['password']) && $body['password'] === $secret) {
            $flag = $secret;
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
    <title>Level 7 — <?= htmlspecialchars($levelTitle) ?> | NoSQL Injection Lab</title>
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
        <span class="level-badge">Level 7</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-hard">Hard</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level7.php — blind login: one bit of feedback, $regex only</span>
<span class="php-variable">$users</span> = <span class="php-function">nosql_get_users</span>();
<span class="php-variable">$body</span>  = <span class="php-function">json_decode</span>(<span class="php-variable">$_POST</span>[<span class="php-string">'query'</span>], <span class="php-keyword">true</span>);

<span class="php-comment">// Only $regex survives; $ne / $gt / $where / $in are all rejected</span>
<span class="php-keyword">foreach</span> (<span class="php-function">operators_used</span>(<span class="php-variable">$body</span>) <span class="php-keyword">as</span> <span class="php-variable">$op</span>)
    <span class="php-keyword">if</span> (<span class="php-variable">$op</span> !== <span class="php-string">'$regex'</span>) <span class="php-function">reject</span>();

<span class="vuln-line"><span class="php-variable">$query</span> = [<span class="php-string">'username'</span> =&gt; <span class="php-variable">$body</span>[<span class="php-string">'username'</span>], <span class="php-string">'password'</span> =&gt; <span class="php-variable">$body</span>[<span class="php-string">'password'</span>]];</span>
<span class="php-variable">$ok</span>    = <span class="php-function">nosql_has_admin</span>(<span class="php-function">mongo_find</span>(<span class="php-variable">$users</span>, <span class="php-variable">$query</span>));
<span class="php-keyword">echo</span> <span class="php-variable">$ok</span> ? <span class="php-string">'Login successful'</span> : <span class="php-string">'Login failed'</span>;<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; Blocking every operator except <code>$regex</code> does not
                help — <code>$regex</code> alone is a perfect boolean oracle. Each anchored probe
                (<code>^F</code>, <code>^FL</code>, …) flips the single success bit, letting you rebuild the
                hidden password one character at a time.
            </div>
        </div>

        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>This login returns <strong>only</strong> "Login successful" or "Login failed" — no counts,
                no data. Auth-bypass operators are blocked, leaving just <code>$regex</code>.</p>
                <p>That one bit is enough: extract the admin password (the flag) character by character.</p>
            </div>

            <form method="post" action="level7.php">
                <div class="form-group">
                    <label class="form-label" for="query_input">Login request body (JSON)</label>
                    <textarea id="query_input" name="query" class="form-control" rows="4" spellcheck="false"
                        placeholder='{"username":"admin","password":{"$regex":"^F"}}'><?= htmlspecialchars($raw) ?></textarea>
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Attempt Login</button>
                    <?php if ($raw !== ''): ?>
                    <a href="level7.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($blockedOp !== ''): ?>
            <div class="message error">&#x1F6AB; Operator <code><?= htmlspecialchars($blockedOp) ?></code> is not allowed here. Only <code>$regex</code> is permitted.</div>
            <?php endif; ?>

            <?php if ($jsonErr !== ''): ?>
            <div class="message error"><?= htmlspecialchars($jsonErr) ?></div>
            <?php endif; ?>

            <?php if ($query !== null && $blockedOp === '' && $jsonErr === ''): ?>
                <?php if ($loginOk): ?>
                    <div class="oracle match">&#x2714; Login successful</div>
                <?php else: ?>
                    <div class="oracle nomatch">&#x2717; Login failed</div>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; Flag reconstructed!</h3>
                <p>You recovered the entire admin password from a single boolean oracle.</p>
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
