<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 7;
$levelTitle = '__wakeup Bypass (CVE-2016-7124)';
$nextLevel  = 8;

// ── Gadget class (also shown in the source panel) ────────────
class SecureSession {
    public $file = '/tmp/session_default';
    public function __wakeup() {
        // "self-defence": reset the path on every unserialize
        $this->file = '/tmp/session_default';
    }
    public function load() {
        return (string)@file_get_contents($this->file);
    }
}

/**
 * Faithfully reproduces PHP < 7.0.10 unserialize() for a flat object:
 * when the declared property count is GREATER than the number of
 * properties actually present, the old engine SKIPPED __wakeup() and kept
 * the attacker's properties (CVE-2016-7124). PHP 7.0.10+/8.x instead make
 * unserialize() return false, so this level emulates the historical bug.
 *
 * @return array{0: mixed, 1: bool, 2: int, 3: int}  [object, wakeupSkipped, declared, actual]
 */
function poi_l7_unserialize(string $blob): array {
    if (!preg_match('/^O:\d+:"([^"]+)":(\d+):\{(.*)\}$/s', $blob, $m)) {
        return [@unserialize($blob), false, 0, 0];
    }
    $class = $m[1]; $declared = (int)$m[2]; $body = $m[3];
    preg_match_all('/s:\d+:"([^"]*)";(s:\d+:"[^"]*"|i:-?\d+|b:[01]|N);/s', $body, $pm, PREG_SET_ORDER);
    $actual = count($pm);
    if ($declared > $actual && class_exists($class)) {
        $obj = new $class();                       // build WITHOUT __wakeup()
        foreach ($pm as $p) {
            $obj->{$p[1]} = @unserialize($p[2] . ';');
        }
        return [$obj, true, $declared, $actual];
    }
    return [@unserialize($blob), false, $declared, $actual];   // safe path: __wakeup runs
}

// ── Challenge logic (the REAL vulnerable code) ───────────────
$blob = $_GET['session'] ?? '';
$ran = false;
$captured = '';
$skipped = false;
$declared = 0;
$actual = 0;

if ($blob !== '') {
    [$obj, $skipped, $declared, $actual] = poi_l7_unserialize($blob);  // ← SINK
    if ($obj instanceof SecureSession) {
        $captured = $obj->load();
    }
    $ran = true;
}

$flag = poi_contains_secret($captured) ? get_flag_for_level($levelId) : '';

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 7 — __wakeup Bypass | PHP Object Injection Lab</title>
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
        <span class="level-badge">Level 7</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-hard">Hard</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level7.php — "secure" session loader</span>
<span class="php-keyword">class</span> <span class="php-function">SecureSession</span> {
    <span class="php-keyword">public</span> <span class="php-variable">$file</span> = <span class="php-string">'/tmp/session_default'</span>;
    <span class="php-keyword">public function</span> <span class="php-function">__wakeup</span>() {
        <span class="php-variable">$this</span>-&gt;file = <span class="php-string">'/tmp/session_default'</span>; <span class="php-comment">// sanitise on load</span>
    }
    <span class="php-keyword">public function</span> <span class="php-function">load</span>() {
        <span class="php-keyword">return</span> <span class="php-function">file_get_contents</span>(<span class="php-variable">$this</span>-&gt;file);
    }
}

<span class="php-variable">$blob</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'session'</span>] ?? <span class="php-string">''</span>;
<span class="vuln-line"><span class="php-variable">$obj</span> = <span class="php-function">unserialize</span>(<span class="php-variable">$blob</span>); <span class="php-comment">// count &gt; actual =&gt; __wakeup skipped</span></span>
<span class="php-keyword">echo</span> <span class="php-variable">$obj</span>-&gt;<span class="php-function">load</span>();
<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>CVE-2016-7124:</strong>&nbsp; <code>__wakeup()</code> would normally sanitise
                <code>$this->file</code>. But in PHP &lt; 7.0.10, declaring a property <em>count larger than the
                number of properties present</em> made the engine skip <code>__wakeup()</code> entirely, so the
                injected <code>file</code> survived. This level reproduces that historical engine behaviour on
                PHP 8.2 (modern PHP returns <code>false</code> instead).
            </div>
        </div>

        <div class="challenge-panel">
            <h3>Challenge</h3>

            <div class="scenario">
                <p>The session loader "defends itself" by resetting <code>$this->file</code> in
                <code>__wakeup()</code>. A well-formed object always gets sanitised.</p>
                <p>Craft a <code>SecureSession</code> that points <code>file</code> at the secret, then bump the
                declared property count so <code>__wakeup()</code> never runs.</p>
            </div>

            <form method="get" action="level7.php">
                <div class="form-group">
                    <label class="form-label" for="session_input">Serialized <code>session</code> (GET)</label>
                    <input
                        type="text"
                        id="session_input"
                        name="session"
                        class="form-control"
                        placeholder='O:13:"SecureSession":2:{...one property...}'
                        value="<?= htmlspecialchars($blob) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Load Session</button>
                    <?php if ($blob !== ''): ?>
                    <a href="level7.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; __wakeup() Skipped!</h3>
                <p>The count mismatch bypassed sanitisation and <code>load()</code> read the secret.</p>
                <code><?= htmlspecialchars($flag) ?></code>
                <p style="margin-top:0.75rem;"><a href="submit.php" style="color:#818cf8;">Submit this flag &rarr;</a></p>
            </div>
            <?php elseif ($ran): ?>
            <div class="message error"><?= $skipped ? 'Wakeup was skipped, but the file did not reach the secret. Set <code>file</code> to <code>/var/secret/flag.txt</code>.' : '__wakeup() ran and sanitised the path. Declare MORE properties than you list so it is skipped.' ?></div>
            <?php endif; ?>

            <?php if ($ran): ?>
            <div class="output-section">
                <h4>Engine trace</h4>
                <div class="output-box">declared properties : <?= (int)$declared ?>
actual properties   : <?= (int)$actual ?>
__wakeup() skipped  : <?= $skipped ? 'YES (CVE-2016-7124)' : 'no' ?>
load() output       : <?= htmlspecialchars(trim($captured) === '' ? '(empty)' : substr(trim($captured), 0, 400)) ?></div>
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
