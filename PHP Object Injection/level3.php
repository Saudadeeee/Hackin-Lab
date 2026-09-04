<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 3;
$levelTitle = '__wakeup Gadget';
$nextLevel  = 4;

// ── Gadget class (also shown in the source panel) ────────────
class SessionStore {
    public $file = '';
    public $data = '';
    public function __wakeup() {
        // PHP calls this automatically *during* unserialize()
        if ($this->file !== '') {
            $this->data = @file_get_contents($this->file);
        }
    }
}

// ── Challenge logic (the REAL vulnerable code) ───────────────
$blob = $_GET['data'] ?? '';
$ran = false;
$captured = '';

if ($blob !== '') {
    $obj = @unserialize($blob);   // ← SINK: __wakeup() fires right here
    if ($obj instanceof SessionStore) {
        $captured = (string)$obj->data;
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
    <title>Level 3 — __wakeup Gadget | PHP Object Injection Lab</title>
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
        <span class="level-badge">Level 3</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level3.php — session restorer</span>
<span class="php-keyword">class</span> <span class="php-function">SessionStore</span> {
    <span class="php-keyword">public</span> <span class="php-variable">$file</span> = <span class="php-string">''</span>;
    <span class="php-keyword">public</span> <span class="php-variable">$data</span> = <span class="php-string">''</span>;
    <span class="php-keyword">public function</span> <span class="php-function">__wakeup</span>() {    <span class="php-comment">// runs during unserialize()</span>
        <span class="php-keyword">if</span> (<span class="php-variable">$this</span>-&gt;file !== <span class="php-string">''</span>)
            <span class="php-variable">$this</span>-&gt;data = <span class="php-function">file_get_contents</span>(<span class="php-variable">$this</span>-&gt;file);
    }
}

<span class="php-variable">$blob</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'data'</span>] ?? <span class="php-string">''</span>;
<span class="vuln-line"><span class="php-variable">$obj</span> = <span class="php-function">unserialize</span>(<span class="php-variable">$blob</span>);  <span class="php-comment">// __wakeup() fires immediately</span></span>
<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Gadget:</strong>&nbsp; Unlike a destructor, <code>__wakeup()</code> runs the moment
                <code>unserialize()</code> parses the object — you do not have to use the object at all.
                It reads <code>$this->file</code>, and you control that property.
            </div>
        </div>

        <div class="challenge-panel">
            <h3>Challenge</h3>

            <div class="scenario">
                <p>A "resume session" feature unserializes the <code>data</code> parameter to restore a
                cached <code>SessionStore</code>. During restoration, <code>__wakeup()</code> pre-loads the
                store's backing file.</p>
                <p>Send a <code>SessionStore</code> whose <code>file</code> is the secret path.</p>
            </div>

            <form method="get" action="level3.php">
                <div class="form-group">
                    <label class="form-label" for="data_input">Serialized <code>data</code> object (GET)</label>
                    <input
                        type="text"
                        id="data_input"
                        name="data"
                        class="form-control"
                        placeholder='O:12:"SessionStore":1:{...}'
                        value="<?= htmlspecialchars($blob) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Resume Session</button>
                    <?php if ($blob !== ''): ?>
                    <a href="level3.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; Gadget Triggered!</h3>
                <p><code>__wakeup()</code> read the secret during unserialize().</p>
                <code><?= htmlspecialchars($flag) ?></code>
                <p style="margin-top:0.75rem;"><a href="submit.php" style="color:#6f9fb0;">Submit this flag &rarr;</a></p>
            </div>
            <?php elseif ($ran): ?>
            <div class="message error"><code>__wakeup()</code> ran but did not reach the secret. Set <code>file</code> to <code>/var/secret/flag.txt</code>.</div>
            <?php endif; ?>

            <?php if ($ran): ?>
            <div class="output-section">
                <h4>__wakeup() read result</h4>
                <div class="output-box <?= trim($captured) === '' ? 'empty' : '' ?>"><?= $captured === '' ? '(no file was read)' : htmlspecialchars(substr(trim($captured), 0, 800)) ?></div>
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
