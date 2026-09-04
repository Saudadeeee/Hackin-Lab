<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 5;
$levelTitle = 'POP Chain (Two Gadgets)';
$nextLevel  = 6;

// ── Gadget classes (also shown in the source panel) ──────────
class FileViewer {
    public $source = '';
    public function flush() {
        return (string)@file_get_contents($this->source);
    }
}
class Logger {
    public $writer;
    public function __destruct() {
        if (is_object($this->writer) && method_exists($this->writer, 'flush')) {
            echo $this->writer->flush();   // calls into the inner gadget
        }
    }
}

// ── Challenge logic (the REAL vulnerable code) ───────────────
$blob = $_GET['q'] ?? '';
$ran = false;
$captured = '';

if ($blob !== '') {
    ob_start();
    $obj = @unserialize($blob);   // ← SINK: attacker-controlled
    unset($obj);                  // Logger::__destruct() -> FileViewer::flush()
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
    <title>Level 5 — POP Chain | PHP Object Injection Lab</title>
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
        <span class="level-badge">Level 5</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level5.php — buffered logger</span>
<span class="php-keyword">class</span> <span class="php-function">FileViewer</span> {
    <span class="php-keyword">public</span> <span class="php-variable">$source</span> = <span class="php-string">''</span>;
    <span class="php-keyword">public function</span> <span class="php-function">flush</span>() {
        <span class="php-keyword">return</span> <span class="php-function">file_get_contents</span>(<span class="php-variable">$this</span>-&gt;source);
    }
}
<span class="php-keyword">class</span> <span class="php-function">Logger</span> {
    <span class="php-keyword">public</span> <span class="php-variable">$writer</span>;
    <span class="php-keyword">public function</span> <span class="php-function">__destruct</span>() {
        <span class="php-keyword">echo</span> <span class="php-variable">$this</span>-&gt;writer-&gt;<span class="php-function">flush</span>(); <span class="php-comment">// -&gt; inner gadget</span>
    }
}

<span class="php-variable">$blob</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'q'</span>] ?? <span class="php-string">''</span>;
<span class="vuln-line"><span class="php-variable">$obj</span> = <span class="php-function">unserialize</span>(<span class="php-variable">$blob</span>);  <span class="php-comment">// attacker-controlled sink</span></span>
<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>POP chain:</strong>&nbsp; <code>Logger</code> has the destructor, but it does no file I/O
                itself — it calls <code>flush()</code> on whatever object sits in <code>$this->writer</code>.
                Put a <code>FileViewer</code> there and <em>its</em> <code>flush()</code> does the read. You
                assemble the "gadget chain" by nesting one object inside the other.
            </div>
        </div>

        <div class="challenge-panel">
            <h3>Challenge</h3>

            <div class="scenario">
                <p>A logger flushes its <code>writer</code> when torn down. The writer can be any object with
                a <code>flush()</code> method. Chain a <code>FileViewer</code> (which reads a file) into the
                <code>Logger</code>'s <code>writer</code> property.</p>
                <p>Nested object = the inner <code>O:...:{...}</code> pasted directly as the property value
                (no trailing semicolon).</p>
            </div>

            <form method="get" action="level5.php">
                <div class="form-group">
                    <label class="form-label" for="q_input">Serialized <code>q</code> chain (GET)</label>
                    <input
                        type="text"
                        id="q_input"
                        name="q"
                        class="form-control"
                        placeholder='O:6:"Logger":1:{s:6:"writer";O:10:"FileViewer":1:{...}}'
                        value="<?= htmlspecialchars($blob) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Flush Logger</button>
                    <?php if ($blob !== ''): ?>
                    <a href="level5.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; Chain Fired!</h3>
                <p>Logger&rarr;FileViewer executed and read the secret.</p>
                <code><?= htmlspecialchars($flag) ?></code>
                <p style="margin-top:0.75rem;"><a href="submit.php" style="color:#6f9fb0;">Submit this flag &rarr;</a></p>
            </div>
            <?php elseif ($ran): ?>
            <div class="message error">Chain did not reach the secret. Nest a <code>FileViewer</code> (with <code>source</code> = the secret path) inside <code>writer</code>.</div>
            <?php endif; ?>

            <?php if ($ran): ?>
            <div class="output-section">
                <h4>Chain output</h4>
                <div class="output-box <?= trim($captured) === '' ? 'empty' : '' ?>"><?= trim($captured) === '' ? '(chain produced no output)' : htmlspecialchars(substr(trim($captured), 0, 800)) ?></div>
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
