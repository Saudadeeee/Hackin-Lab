<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 6;
$levelTitle = 'Type-Juggling Auth Bypass';
$nextLevel  = 7;

// ── Gadget class (also shown in the source panel) ────────────
class AuthToken {
    public $user     = '';
    public $password = '';
}

// Stored admin password hash — a PHP "magic hash" (0e followed by digits).
$ADMIN_HASH = '0e462097431906509019562988736854';

// ── Challenge logic (the REAL vulnerable code) ───────────────
$blob = $_POST['auth_token'] ?? ($_COOKIE['auth_token'] ?? '');
$ran = false;
$granted = false;
$secret = '';
$obj = null;

if ($blob !== '') {
    $obj = @unserialize($blob);                    // ← SINK: attacker-controlled
    if ($obj instanceof AuthToken
        && $obj->password !== $ADMIN_HASH          // block a literal replay
        && $obj->password == $ADMIN_HASH) {        // ...but compare loosely (BUG)
        $secret  = @file_get_contents(poi_secret_path());
        $granted = true;
    }
    $ran = true;
}

$flag = ($granted && poi_contains_secret($secret)) ? get_flag_for_level($levelId) : '';

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 6 — Type-Juggling Auth Bypass | PHP Object Injection Lab</title>
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
        <span class="level-badge">Level 6</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level6.php — token login</span>
<span class="php-keyword">class</span> <span class="php-function">AuthToken</span> {
    <span class="php-keyword">public</span> <span class="php-variable">$user</span> = <span class="php-string">''</span>;
    <span class="php-keyword">public</span> <span class="php-variable">$password</span> = <span class="php-string">''</span>;
}
<span class="php-variable">$ADMIN_HASH</span> = <span class="php-string">'0e462097431906509019562988736854'</span>;

<span class="php-variable">$t</span> = <span class="php-function">unserialize</span>(<span class="php-variable">$_COOKIE</span>[<span class="php-string">'auth_token'</span>]); <span class="php-comment">// attacker-controlled</span>
<span class="php-keyword">if</span> (<span class="php-variable">$t</span>-&gt;password !== <span class="php-variable">$ADMIN_HASH</span>       <span class="php-comment">// not a literal replay</span>
<span class="vuln-line"> &amp;&amp; <span class="php-variable">$t</span>-&gt;password == <span class="php-variable">$ADMIN_HASH</span>) {    <span class="php-comment">// loose == : magic-hash juggling</span></span>
    <span class="php-function">grant_admin</span>();  <span class="php-comment">// reads /var/secret/flag.txt</span>
}<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Bug:</strong>&nbsp; The stored hash is a <em>magic hash</em> (<code>0e</code> + digits).
                PHP's loose <code>==</code> reads any <code>0e[digits]</code> string as <code>0 &times; 10^n = 0</code>,
                so two different magic hashes compare equal. The <code>!==</code> guard blocks copying the exact
                value, but a <em>different</em> magic hash in the injected <code>password</code> still passes.
            </div>
        </div>

        <div class="challenge-panel">
            <h3>Challenge</h3>

            <div class="scenario">
                <p>Login accepts a serialized <code>AuthToken</code> from your session cookie and checks the
                <code>password</code> against the admin hash with <code>==</code>. You cannot replay the exact
                stored value, but you don't need to.</p>
                <p>Inject an <code>AuthToken</code> whose <code>password</code> is a <em>different</em>
                <code>0e</code> magic hash.</p>
            </div>

            <form method="post" action="level6.php">
                <div class="form-group">
                    <label class="form-label" for="auth_input">Serialized <code>auth_token</code> (POST or cookie)</label>
                    <input
                        type="text"
                        id="auth_input"
                        name="auth_token"
                        class="form-control"
                        placeholder='O:9:"AuthToken":2:{...}'
                        value="<?= htmlspecialchars($blob) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Login</button>
                    <?php if ($blob !== ''): ?>
                    <a href="level6.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; Logged in as admin!</h3>
                <p>Two different magic hashes compared equal under <code>==</code>.</p>
                <code><?= htmlspecialchars($flag) ?></code>
                <p style="margin-top:0.75rem;"><a href="submit.php" style="color:#818cf8;">Submit this flag &rarr;</a></p>
            </div>
            <?php elseif ($ran): ?>
            <div class="message error">Login failed. The <code>password</code> must be a <em>different</em> <code>0e</code>+digits magic hash than the stored one.</div>
            <?php endif; ?>

            <?php if ($ran && $obj instanceof AuthToken): ?>
            <div class="output-section">
                <h4>Server-side check</h4>
                <div class="output-box">user     = <?= htmlspecialchars(var_export($obj->user, true)) ?>
password = <?= htmlspecialchars(var_export($obj->password, true)) ?>
loose == admin hash : <?= ($obj->password == $ADMIN_HASH) ? 'true' : 'false' ?></div>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <?= render_hint_section($hints) ?>
    <?= render_payload_builder() ?>
    <?= render_inline_flag_form($levelId, $_flag_result) ?>

    <div class="navigation">
        <a href="index.php" class="btn btn-secondary">&larr; Home</a>
        <a href="submit.php" class="btn btn-secondary nav-center">Submit Flag</a>
        <a href="level<?= $nextLevel ?>.php" class="btn btn-secondary">Level <?= $nextLevel ?> &rarr;</a>
    </div>

</div>
</body>
</html>
