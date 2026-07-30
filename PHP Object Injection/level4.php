<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 4;
$levelTitle = '__toString Gadget';
$nextLevel  = 5;

// ── Gadget class (also shown in the source panel) ────────────
class Template {
    public $view = '';
    public function __toString() {
        return (string)@file_get_contents($this->view);
    }
}

// ── Challenge logic (the REAL vulnerable code) ───────────────
$blob = $_POST['tpl'] ?? '';
$ran = false;
$preview = '';

if ($blob !== '') {
    $obj = @unserialize($blob);               // ← SINK: attacker-controlled
    if (is_object($obj) && method_exists($obj, '__toString')) {
        $preview = 'Preview: ' . $obj;        // string cast fires __toString()
    }
    $ran = true;
}

$flag = poi_contains_secret($preview) ? get_flag_for_level($levelId) : '';

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 4 — __toString Gadget | PHP Object Injection Lab</title>
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
        <span class="level-badge">Level 4</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level4.php — template preview</span>
<span class="php-keyword">class</span> <span class="php-function">Template</span> {
    <span class="php-keyword">public</span> <span class="php-variable">$view</span> = <span class="php-string">''</span>;
    <span class="php-keyword">public function</span> <span class="php-function">__toString</span>() {
        <span class="php-keyword">return</span> <span class="php-function">file_get_contents</span>(<span class="php-variable">$this</span>-&gt;view); <span class="php-comment">// reads any path</span>
    }
}

<span class="php-variable">$blob</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'tpl'</span>] ?? <span class="php-string">''</span>;
<span class="vuln-line"><span class="php-variable">$obj</span> = <span class="php-function">unserialize</span>(<span class="php-variable">$blob</span>);  <span class="php-comment">// attacker-controlled sink</span></span>
<span class="php-keyword">echo</span> <span class="php-string">"Preview: "</span> . <span class="php-variable">$obj</span>;   <span class="php-comment">// string cast -&gt; __toString()</span>
<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Gadget:</strong>&nbsp; Concatenating an object into a string casts it, which invokes
                <code>Template::__toString()</code>. That method returns the contents of <code>$this->view</code>
                — a path you control through the injected object. No destructor or wakeup needed; the
                <em>echo</em> alone triggers the read.
            </div>
        </div>

        <div class="challenge-panel">
            <h3>Challenge</h3>

            <div class="scenario">
                <p>A template preview endpoint unserializes the <code>tpl</code> parameter and echoes a
                preview string built from it. The string cast fires <code>__toString()</code>.</p>
                <p>Send a <code>Template</code> whose <code>view</code> is the secret path.</p>
            </div>

            <form method="post" action="level4.php">
                <div class="form-group">
                    <label class="form-label" for="tpl_input">Serialized <code>tpl</code> object (POST)</label>
                    <input
                        type="text"
                        id="tpl_input"
                        name="tpl"
                        class="form-control"
                        placeholder='O:8:"Template":1:{...}'
                        value="<?= htmlspecialchars($blob) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Render Preview</button>
                    <?php if ($blob !== ''): ?>
                    <a href="level4.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; Gadget Triggered!</h3>
                <p>The string cast fired <code>__toString()</code> and it read the secret.</p>
                <code><?= htmlspecialchars($flag) ?></code>
                <p style="margin-top:0.75rem;"><a href="submit.php" style="color:#818cf8;">Submit this flag &rarr;</a></p>
            </div>
            <?php elseif ($ran): ?>
            <div class="message error">No secret in the preview. Send a <code>Template</code> with <code>view</code> = <code>/var/secret/flag.txt</code>.</div>
            <?php endif; ?>

            <?php if ($ran): ?>
            <div class="output-section">
                <h4>Rendered preview</h4>
                <div class="output-box <?= trim($preview) === '' ? 'empty' : '' ?>"><?= trim($preview) === '' ? '(nothing rendered — was it a Template with __toString?)' : htmlspecialchars(substr($preview, 0, 800)) ?></div>
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
