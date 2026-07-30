<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 2;
$levelTitle = '__destruct File-Read Gadget';
$nextLevel  = 3;

// ── Gadget class (also shown in the source panel) ────────────
class TempFile {
    public $path = '';
    public function __destruct() {
        if ($this->path !== '') {
            echo @file_get_contents($this->path);
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
    unset($obj);                  // __destruct() fires here
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
    <title>Level 2 — __destruct File Read | PHP Object Injection Lab</title>
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
        <span class="level-badge">Level 2</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-easy">Easy</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level2.php — temp-file cleanup service</span>
<span class="php-keyword">class</span> <span class="php-function">TempFile</span> {
    <span class="php-keyword">public</span> <span class="php-variable">$path</span> = <span class="php-string">''</span>;
    <span class="php-keyword">public function</span> <span class="php-function">__destruct</span>() {   <span class="php-comment">// fires when object is freed</span>
        <span class="php-keyword">if</span> (<span class="php-variable">$this</span>-&gt;path !== <span class="php-string">''</span>)
            <span class="php-keyword">echo</span> <span class="php-function">file_get_contents</span>(<span class="php-variable">$this</span>-&gt;path); <span class="php-comment">// reads any path</span>
    }
}

<span class="php-variable">$blob</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'blob'</span>] ?? <span class="php-string">''</span>;
<span class="vuln-line"><span class="php-variable">$obj</span> = <span class="php-function">unserialize</span>(<span class="php-variable">$blob</span>);  <span class="php-comment">// attacker-controlled sink</span></span>
<span class="php-function">unset</span>(<span class="php-variable">$obj</span>);  <span class="php-comment">// __destruct() runs -&gt; file read</span>
<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Gadget:</strong>&nbsp; <code>TempFile::__destruct()</code> reads whatever path is
                stored in <code>$this->path</code>. Because <code>unserialize()</code> lets you set that
                property, destroying a forged <code>TempFile</code> reads any file on the server —
                point it at <code>/var/secret/flag.txt</code>.
            </div>
        </div>

        <div class="challenge-panel">
            <h3>Challenge</h3>

            <div class="scenario">
                <p>A cleanup service unserializes a queued <code>TempFile</code> job and lets it fall out
                of scope, firing the destructor. The destructor reads the file path it was given.</p>
                <p>Submit a serialized <code>TempFile</code> whose <code>path</code> points at the secret.</p>
            </div>

            <form method="post" action="level2.php">
                <div class="form-group">
                    <label class="form-label" for="blob_input">Serialized <code>blob</code> (POST)</label>
                    <input
                        type="text"
                        id="blob_input"
                        name="blob"
                        class="form-control"
                        placeholder='O:8:"TempFile":1:{...}'
                        value="<?= htmlspecialchars($blob) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Queue Job</button>
                    <?php if ($blob !== ''): ?>
                    <a href="level2.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; Gadget Triggered!</h3>
                <p>The destructor read the secret file.</p>
                <code><?= htmlspecialchars($flag) ?></code>
                <p style="margin-top:0.75rem;"><a href="submit.php" style="color:#818cf8;">Submit this flag &rarr;</a></p>
            </div>
            <?php elseif ($ran): ?>
            <div class="message error">The destructor ran, but it did not reach the secret. Set <code>path</code> to <code>/var/secret/flag.txt</code>.</div>
            <?php endif; ?>

            <?php if ($ran): ?>
            <div class="output-section">
                <h4>Destructor output (file read)</h4>
                <div class="output-box <?= trim($captured) === '' ? 'empty' : '' ?>"><?= $captured === '' ? '(destructor produced no output)' : htmlspecialchars(substr(trim($captured), 0, 800)) ?></div>
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
