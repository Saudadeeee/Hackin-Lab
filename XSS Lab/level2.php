<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 2;
$levelTitle = 'XSS in HTML Attribute';
$prevLevel  = 1;
$nextLevel  = 3;

// ── Challenge logic ──────────────────────────────────────────
$search = $_GET['q'] ?? '';

$flag        = '';
$flagMessage = '';

if ($search !== '' && verify_xss_payload($levelId, $search)) {
    $flag        = get_flag_for_level($levelId);
    $flagMessage = 'XSS attribute escape confirmed server-side!';
}

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 2 — XSS in HTML Attribute | XSS Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>

<header class="header">
    <a href="index.php" class="back-btn">&larr; Back to Levels</a>
    <div class="header-title"><span style="color:var(--primary)">&#x26A1;</span> XSS Lab</div>
    <a href="submit.php" class="submit-link">Submit Flag</a>
</header>

<div class="container">

    <div class="level-header">
        <span class="level-badge">Level 2</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-easy">Easy</span>
    </div>

    <div class="challenge-layout">

        <!-- ── Left: Source Code Panel ── -->
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-variable">$search</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'q'</span>] ?? <span class="php-string">''</span>;
<span class="php-keyword">?&gt;</span>

<span class="php-comment">&lt;!-- value attribute: ENT_NOQUOTES does NOT escape " --&gt;</span>
<span class="vuln-line">&lt;input type=<span class="php-string">"text"</span> name=<span class="php-string">"q"</span> value=<span class="php-string">"&lt;?= htmlspecialchars($search, ENT_NOQUOTES) ?&gt;"</span>&gt;</span>
<span class="php-comment">&lt;!-- p tag: ENT_QUOTES correctly escapes both quote types --&gt;</span>
&lt;p&gt;You searched for:
  &lt;?= htmlspecialchars(<span class="php-variable">$search</span>, ENT_QUOTES) ?&gt;
&lt;/p&gt;</code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp;
                <code>ENT_NOQUOTES</code> leaves the double-quote character (<code>"</code>) unescaped.
                Inside a double-quoted attribute (<code>value="..."</code>), an injected <code>"</code>
                closes the attribute and lets you inject new attributes — including event handlers.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>A search form reflects your query back into the <code>value</code> attribute
                of an <code>&lt;input&gt;</code> element using <code>htmlspecialchars($search, ENT_NOQUOTES)</code>.</p>
                <p>The developer used <code>ENT_NOQUOTES</code> instead of <code>ENT_QUOTES</code>,
                which means <strong>double quotes are not escaped</strong>. Break out of the
                <code>value="..."</code> context and inject a JavaScript event handler.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level2.php">
                <div class="form-group">
                    <label class="form-label" for="q_input">XSS Payload (q parameter)</label>
                    <input
                        type="text"
                        id="q_input"
                        name="q"
                        class="form-control"
                        placeholder='e.g. " onmouseover="alert(1)'
                        value="<?= htmlspecialchars($search) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Submit Payload</button>
                    <?php if ($search !== ''): ?>
                    <a href="level2.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <!-- Flag / result display -->
            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; Flag Captured!</h3>
                <p><?= htmlspecialchars($flagMessage) ?></p>
                <code><?= htmlspecialchars($flag) ?></code>
                <p style="margin-top:0.75rem; font-size:0.8rem;">
                    <a href="submit.php">Submit this flag &rarr;</a>
                </p>
            </div>
            <?php elseif ($search !== ''): ?>
            <div class="message error">
                Payload not accepted. Remember: you must inject a <code>"</code> to break out of
                the attribute and then add an event handler.
            </div>
            <?php endif; ?>

            <!-- ── Live vulnerable output ── -->
            <div class="xss-output-section">
                <h4>Live Output (vulnerable input element):</h4>
                <div class="xss-output-box" style="padding:0.5rem 0.75rem;">
                    <!--
                        THIS IS THE ACTUAL VULNERABILITY:
                        The value attribute uses ENT_NOQUOTES — double quotes pass through unescaped.
                    -->
                    <input type="text" name="q"
                           value="<?= htmlspecialchars($search, ENT_NOQUOTES) ?>"
                           placeholder="Search..."
                           style="width:100%; background:var(--surface2); color:var(--text);
                                  border:1px solid var(--border); padding:0.4rem 0.6rem;
                                  border-radius:4px; font-family:inherit;">
                </div>
                <?php if ($search !== ''): ?>
                <div style="margin-top:0.6rem; padding:0.5rem 0.75rem; background:var(--bg);
                            border:1px solid var(--border); border-radius:var(--radius); font-size:0.85rem;">
                    <span style="color:var(--text-muted);">Properly escaped (ENT_QUOTES):</span>
                    <?= htmlspecialchars($search, ENT_QUOTES) ?>
                </div>
                <?php endif; ?>
                <p class="xss-sandbox-note">
                    The <code>value</code> attribute uses <code>ENT_NOQUOTES</code>. Inspect the page source
                    to see how your <code>"</code> character breaks the attribute context.
                </p>
            </div>

        </div><!-- /.challenge-panel -->
    </div><!-- /.challenge-layout -->

    <?= render_hint_section($hints) ?>
    <?= render_inline_flag_form($levelId, $_flag_result) ?>

    <div class="navigation">
        <a href="level<?= $prevLevel ?>.php" class="btn btn-secondary">&larr; Level <?= $prevLevel ?></a>
        <a href="submit.php" class="btn btn-secondary nav-center">Submit Flag</a>
        <a href="level<?= $nextLevel ?>.php" class="btn btn-secondary">Level <?= $nextLevel ?> &rarr;</a>
    </div>

</div><!-- /.container -->
</body>
</html>
