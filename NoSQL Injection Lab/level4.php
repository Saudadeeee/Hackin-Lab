<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/mongo.php';

$levelId    = 4;
$levelTitle = '$regex Password Extraction';
$prevLevel  = 3;
$nextLevel  = 5;

// ── Challenge logic ──────────────────────────────────────────
// For this level the admin's password IS the flag; it lives only in the
// document store and is never printed. It must be recovered via $regex.
$users  = nosql_get_users($levelId);
$secret = get_flag_for_level($levelId);   // = admin password in the doc store

$raw = $_POST['query'] ?? '';
[$body, $jsonErr] = nosql_json($raw);

$query        = null;
$matchedAdmin = false;
$flag         = '';
$regexUsed    = '';

if ($body !== null) {
    // VULNERABLE: the password operator object is honoured, so $regex probes the secret.
    $query = [
        'username' => $body['username'] ?? '',
        'password' => $body['password'] ?? '',
    ];
    $results      = mongo_find($users, $query);
    $matchedAdmin = nosql_has_admin($results);

    // Extract the regex operand (if any) to detect a full, anchored match.
    if (isset($body['password']) && is_array($body['password']) && isset($body['password']['$regex'])) {
        $regexUsed = (string)$body['password']['$regex'];
    }

    // Award only on genuine full extraction of the secret from the doc store.
    if ($regexUsed !== '' && nosql_regex_fully_matches($regexUsed, $secret)) {
        $flag = $secret;
    } elseif (isset($body['password']) && is_string($body['password']) && $body['password'] === $secret) {
        $flag = $secret;
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
    <title>Level 4 — <?= htmlspecialchars($levelTitle) ?> | NoSQL Injection Lab</title>
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
        <span class="level-badge">Level 4</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level4.php — the admin password is secret and never printed</span>
<span class="php-variable">$users</span> = <span class="php-function">nosql_get_users</span>();
<span class="php-variable">$body</span>  = <span class="php-function">json_decode</span>(<span class="php-variable">$_POST</span>[<span class="php-string">'query'</span>], <span class="php-keyword">true</span>);

<span class="vuln-line"><span class="php-variable">$query</span> = [<span class="php-string">'username'</span> =&gt; <span class="php-variable">$body</span>[<span class="php-string">'username'</span>], <span class="php-string">'password'</span> =&gt; <span class="php-variable">$body</span>[<span class="php-string">'password'</span>]];</span>
<span class="php-variable">$hit</span>   = <span class="php-function">mongo_find</span>(<span class="php-variable">$users</span>, <span class="php-variable">$query</span>);

<span class="php-comment">// Only a match/no-match oracle is returned — never the password itself</span>
<span class="php-keyword">echo</span> <span class="php-variable">$hit</span> ? <span class="php-string">'a user matched'</span> : <span class="php-string">'no match'</span>;<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The <code>$regex</code> operator lets you ask yes/no
                questions about the hidden password. <code>{"$regex":"^F"}</code> is true only if it starts
                with <code>F</code>. Iterate character by character to reconstruct the entire secret — which
                is itself the flag.
            </div>
        </div>

        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>The admin password is a secret string the server refuses to display — you only get a
                <strong>match / no-match</strong> oracle. Use <code>$regex</code> to test one character at a
                time: <code>^F</code>, <code>^FL</code>, <code>^FLA</code>, …</p>
                <p>When you have pinned every character with an anchored <code>^...$</code> pattern, the flag
                is captured.</p>
            </div>

            <form method="post" action="level4.php">
                <div class="form-group">
                    <label class="form-label" for="query_input">Probe request body (JSON)</label>
                    <textarea id="query_input" name="query" class="form-control" rows="4" spellcheck="false"
                        placeholder='{"username":"admin","password":{"$regex":"^F"}}'><?= htmlspecialchars($raw) ?></textarea>
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Send Probe</button>
                    <?php if ($raw !== ''): ?>
                    <a href="level4.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($jsonErr !== ''): ?>
            <div class="message error"><?= htmlspecialchars($jsonErr) ?></div>
            <?php endif; ?>

            <?php if ($query !== null && $jsonErr === ''): ?>
            <div class="query-echo"><span class="k">db.users.find(</span><?= htmlspecialchars(nosql_query_repr($query)) ?><span class="k">)</span></div>
                <?php if ($matchedAdmin): ?>
                    <div class="oracle match">&#x2714; A user matched your query.</div>
                <?php else: ?>
                    <div class="oracle nomatch">&#x2717; No user matched your query.</div>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; Secret fully extracted!</h3>
                <p>Your anchored regex pinned every character of the hidden admin password.</p>
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
