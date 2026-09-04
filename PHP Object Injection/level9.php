<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 9;
$levelTitle = 'RCE POP Chain';
$prevLevel  = 8;
$nextLevel  = 10;

// ── Gadget classes (also shown in the source panel) ──────────
class CommandRunner {
    public $cmd = '';
    public function run() {
        if ($this->cmd !== '') {
            return shell_exec($this->cmd);   // ← command execution
        }
        return '';
    }
}
class Report {
    public $engine = null;
    public function __destruct() {
        if (is_object($this->engine) && method_exists($this->engine, 'run')) {
            echo $this->engine->run();       // ← calls into the inner gadget
        }
    }
}

// ── Challenge logic (the REAL vulnerable code) ───────────────
$blob = $_POST['blob'] ?? '';
$ran = false;
$captured = '';

if ($blob !== '') {
    ob_start();                   // capture what the destructor echoes
    $obj = @unserialize($blob);   // ← SINK: attacker-controlled
    unset($obj);                  // Report::__destruct() fires here
    gc_collect_cycles();
    $captured = ob_get_clean();
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
    <title>Level 9 — RCE POP Chain | PHP Object Injection Lab</title>
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
        <span class="level-badge">Level 9</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-hard">Hard</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level9.php — report generator</span>
<span class="php-keyword">class</span> <span class="php-function">CommandRunner</span> {
    <span class="php-keyword">public</span> <span class="php-variable">$cmd</span> = <span class="php-string">''</span>;
    <span class="php-keyword">public function</span> <span class="php-function">run</span>() {
        <span class="php-keyword">return</span> <span class="php-function">shell_exec</span>(<span class="php-variable">$this</span>-&gt;cmd); <span class="php-comment">// runs a shell command</span>
    }
}
<span class="php-keyword">class</span> <span class="php-function">Report</span> {
    <span class="php-keyword">public</span> <span class="php-variable">$engine</span> = <span class="php-keyword">null</span>;
    <span class="php-keyword">public function</span> <span class="php-function">__destruct</span>() {          <span class="php-comment">// fires on free</span>
        <span class="php-keyword">echo</span> <span class="php-variable">$this</span>-&gt;engine-&gt;<span class="php-function">run</span>();          <span class="php-comment">// calls the inner gadget</span>
    }
}

<span class="php-variable">$blob</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'blob'</span>] ?? <span class="php-string">''</span>;
<span class="vuln-line"><span class="php-variable">$obj</span> = <span class="php-function">unserialize</span>(<span class="php-variable">$blob</span>);  <span class="php-comment">// attacker-controlled sink</span></span>
<span class="php-function">unset</span>(<span class="php-variable">$obj</span>);  <span class="php-comment">// Report::__destruct() -&gt; CommandRunner::run() -&gt; RCE</span>
<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>POP chain &rarr; RCE:</strong>&nbsp; <code>Report::__destruct()</code> calls
                <code>run()</code> on whatever object sits in <code>$this->engine</code>. Nest a
                <code>CommandRunner</code> there and its <code>run()</code> executes
                <code>shell_exec($this->cmd)</code>. Point <code>cmd</code> at a command that prints the
                secret: <code>cat /var/secret/flag.txt</code>.
            </div>
        </div>

        <div class="challenge-panel">
            <h3>Challenge</h3>

            <div class="scenario">
                <p>A reporting service unserializes a queued <code>Report</code> job and lets it fall out of
                scope, firing the destructor. The destructor drives an inner "engine" object.</p>
                <p>Chain a <code>CommandRunner</code> inside a <code>Report</code> so the destructor runs your
                command and echoes its output.</p>
            </div>

            <form method="post" action="level9.php">
                <div class="form-group">
                    <label class="form-label" for="blob_input">Serialized <code>blob</code> (POST)</label>
                    <input
                        type="text"
                        id="blob_input"
                        name="blob"
                        class="form-control"
                        placeholder='O:6:"Report":1:{s:6:"engine";O:13:"CommandRunner":1:{...}}'
                        value="<?= htmlspecialchars($blob) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Queue Report</button>
                    <?php if ($blob !== ''): ?>
                    <a href="level9.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; Command Executed!</h3>
                <p>The destructor ran your command through the chained gadget and it printed the secret.</p>
                <code><?= htmlspecialchars($flag) ?></code>
                <p style="margin-top:0.75rem;"><a href="submit.php" style="color:#6f9fb0;">Submit this flag &rarr;</a></p>
            </div>
            <?php elseif ($ran): ?>
            <div class="message error">The chain ran, but the command output did not contain the secret. Try <code>cmd = cat /var/secret/flag.txt</code>.</div>
            <?php endif; ?>

            <?php if ($ran): ?>
            <div class="output-section">
                <h4>Command output (shell_exec)</h4>
                <div class="output-box <?= trim($captured) === '' ? 'empty' : '' ?>"><?= trim($captured) === '' ? '(no output — the chain did not reach shell_exec)' : htmlspecialchars(substr(trim($captured), 0, 800)) ?></div>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <?= render_hint_section($hints) ?>
    <?= render_payload_builder() ?>
    <?= render_inline_flag_form($levelId, $_flag_result) ?>

    <div class="navigation">
        <a href="level<?= $prevLevel ?>.php" class="btn btn-secondary">&larr; Level <?= $prevLevel ?></a>
        <a href="submit.php" class="btn btn-secondary nav-center">Submit Flag</a>
        <a href="level<?= $nextLevel ?>.php" class="btn btn-secondary">Level <?= $nextLevel ?> &rarr;</a>
    </div>

</div>
</body>
</html>
