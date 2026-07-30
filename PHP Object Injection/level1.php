<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 1;
$levelTitle = 'Property Injection — isAdmin Bypass';
$nextLevel  = 2;

// ── Gadget class (also shown in the source panel) ────────────
class Account {
    public $username = 'guest';
    public $isAdmin  = false;
}

// ── Challenge logic (the REAL vulnerable code) ───────────────
$blob = $_GET['account'] ?? '';
$obj      = null;
$granted  = false;
$secret   = '';

if ($blob !== '') {
    $obj = @unserialize($blob);                 // ← SINK: attacker-controlled
    if ($obj instanceof Account && $obj->isAdmin === true) {
        // "Admin dashboard" loads the privileged config file
        $secret  = @file_get_contents(poi_secret_path());
        $granted = true;
    }
}

$flag = ($granted && poi_contains_secret($secret)) ? get_flag_for_level($levelId) : '';

// Build a safe description of what unserialize produced
$resultDesc = '';
if ($blob !== '') {
    if ($obj instanceof Account) {
        $resultDesc = "Account object rebuilt:\n"
                    . "  username = " . var_export($obj->username, true) . "\n"
                    . "  isAdmin  = " . var_export($obj->isAdmin, true);
    } elseif ($obj === false) {
        $resultDesc = "unserialize() returned false (malformed input).";
    } else {
        $resultDesc = "unserialize() returned a " . gettype($obj) . " (not an Account).";
    }
}

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 1 — Property Injection | PHP Object Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <?= render_level_styles() ?>
</head>
<body>

<header class="header">
    <a href="index.php" class="back-btn">&larr; Back to Levels</a>
    <div class="header-title"><span style="color:var(--primary)">&#x1F9E9;</span> PHP Object Injection Lab</div>
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
<span class="php-comment">// level1.php — profile loader</span>
<span class="php-keyword">class</span> <span class="php-function">Account</span> {
    <span class="php-keyword">public</span> <span class="php-variable">$username</span> = <span class="php-string">'guest'</span>;
    <span class="php-keyword">public</span> <span class="php-variable">$isAdmin</span>  = <span class="php-keyword">false</span>;
}

<span class="php-variable">$blob</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'account'</span>] ?? <span class="php-string">''</span>;
<span class="vuln-line"><span class="php-variable">$obj</span> = <span class="php-function">unserialize</span>(<span class="php-variable">$blob</span>);  <span class="php-comment">// attacker controls every property</span></span>
<span class="php-keyword">if</span> (<span class="php-variable">$obj</span> <span class="php-keyword">instanceof</span> Account &amp;&amp; <span class="php-variable">$obj</span>-&gt;isAdmin === <span class="php-keyword">true</span>) {
    <span class="php-comment">// admin dashboard loads the privileged config</span>
    <span class="php-variable">$secret</span> = <span class="php-function">file_get_contents</span>(<span class="php-string">'/var/secret/flag.txt'</span>);
}<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; <code>unserialize()</code> reconstructs an
                <code>Account</code> object directly from user input, so <em>you</em> decide the value of
                every property — including <code>isAdmin</code>. The default is <code>false</code>, but a
                crafted object can set it to boolean <code>true</code> and pass the <code>=== true</code> check.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">
            <h3>Challenge</h3>

            <div class="scenario">
                <p>A profile loader rebuilds your session <code>Account</code> from the
                <code>account</code> parameter and trusts its <code>isAdmin</code> flag. Normal users are
                <code>guest</code> with <code>isAdmin = false</code>.</p>
                <p>Forge a serialized <code>Account</code> whose <code>isAdmin</code> is <code>true</code>.
                When the admin dashboard loads, it reveals the secret and awards the flag.</p>
            </div>

            <form method="get" action="level1.php">
                <div class="form-group">
                    <label class="form-label" for="account_input">Serialized <code>account</code> object</label>
                    <input
                        type="text"
                        id="account_input"
                        name="account"
                        class="form-control"
                        placeholder='O:7:"Account":2:{...}'
                        value="<?= htmlspecialchars($blob) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Load Profile</button>
                    <?php if ($blob !== ''): ?>
                    <a href="level1.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; Gadget Triggered!</h3>
                <p>isAdmin was injected as <code>true</code> — the admin dashboard leaked the secret.</p>
                <code><?= htmlspecialchars($flag) ?></code>
                <p style="margin-top:0.75rem;"><a href="submit.php" style="color:#818cf8;">Submit this flag &rarr;</a></p>
            </div>
            <?php elseif ($blob !== ''): ?>
            <div class="message error">Access denied — you are not an admin yet. Flip <code>isAdmin</code> to boolean <code>true</code>.</div>
            <?php endif; ?>

            <?php if ($resultDesc !== ''): ?>
            <div class="output-section">
                <h4>Server-side result</h4>
                <div class="output-box"><?= htmlspecialchars($resultDesc) ?></div>
                <?php if ($granted): ?>
                <h4>Leaked secret (proof the gadget fired)</h4>
                <div class="output-box"><?= htmlspecialchars(trim($secret)) ?></div>
                <?php endif; ?>
            </div>
            <?php endif; ?>
        </div><!-- /.challenge-panel -->
    </div><!-- /.challenge-layout -->

    <?= render_hint_section($hints) ?>
    <?= render_payload_builder() ?>
    <?= render_inline_flag_form($levelId, $_flag_result) ?>

    <div class="navigation">
        <a href="index.php" class="btn btn-secondary">&larr; Home</a>
        <a href="submit.php" class="btn btn-secondary nav-center">Submit Flag</a>
        <a href="level<?= $nextLevel ?>.php" class="btn btn-secondary">Level <?= $nextLevel ?> &rarr;</a>
    </div>

</div><!-- /.container -->
</body>
</html>
