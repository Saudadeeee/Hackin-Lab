<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 5;
$levelTitle = 'htmlspecialchars Without ENT_QUOTES';
$prevLevel  = 4;
$nextLevel  = 6;

// ── Challenge logic ──────────────────────────────────────────
$bio = $_GET['bio'] ?? '';

// Mimic the vulnerable sanitisation from the code panel
// ENT_COMPAT (default) escapes & < > " — but NOT single quotes
$safe_bio = htmlspecialchars($bio); // default = ENT_COMPAT

$flag        = '';
$flagMessage = '';

if ($bio !== '' && verify_xss_payload($levelId, $bio)) {
    $flag        = get_flag_for_level($levelId);
    $flagMessage = 'Single-quote attribute escape confirmed server-side!';
}

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 5 — htmlspecialchars Without ENT_QUOTES | XSS Lab</title>
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
        <span class="level-badge">Level 5</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">

        <!-- ── Left: Source Code Panel ── -->
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-variable">$bio</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'bio'</span>] ?? <span class="php-string">''</span>;

<span class="php-comment">// Default: ENT_COMPAT — escapes &amp;, &lt;, &gt;, " but NOT '</span>
<span class="php-variable">$safe_bio</span> = htmlspecialchars(<span class="php-variable">$bio</span>);
<span class="php-keyword">?&gt;</span>

<span class="php-comment">&lt;!-- Single-quoted attribute — ' is NOT escaped by ENT_COMPAT --&gt;</span>
<span class="vuln-line">&lt;input type=<span class="php-string">'text'</span> name=<span class="php-string">'bio'</span> value=<span class="php-string">'&lt;?= $safe_bio ?&gt;'</span> /&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp;
                <code>htmlspecialchars()</code> with default flags (<code>ENT_COMPAT</code>)
                does <strong>not</strong> escape the single-quote character (<code>'</code>).
                The attribute is delimited by single quotes, so injecting a <code>'</code>
                closes the <code>value</code> and lets you add arbitrary attributes.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>A profile page reflects the <code>bio</code> GET parameter into a
                <strong>single-quoted</strong> HTML attribute using
                <code>htmlspecialchars($bio)</code> (no second argument — defaults to
                <code>ENT_COMPAT</code>).</p>
                <p><code>ENT_COMPAT</code> encodes double quotes but leaves single quotes
                untouched. Because the attribute uses single-quote delimiters, a
                <code>'</code> in your input escapes the attribute context.</p>
                <p>Your payload must contain a <code>'</code> character <strong>and</strong>
                an event handler to earn the flag.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level5.php">
                <div class="form-group">
                    <label class="form-label" for="bio_input">XSS Payload (bio parameter)</label>
                    <input
                        type="text"
                        id="bio_input"
                        name="bio"
                        class="form-control"
                        placeholder="e.g. ' onfocus='alert(1)' autofocus='"
                        value="<?= htmlspecialchars($bio) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Submit Payload</button>
                    <?php if ($bio !== ''): ?>
                    <a href="level5.php" class="btn btn-secondary">Clear</a>
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
            <?php elseif ($bio !== ''): ?>
            <div class="message error">
                Payload not accepted. Your input must contain a single-quote
                (<code>'</code>) to break out of the attribute AND an event handler.
            </div>
            <?php endif; ?>

            <!-- ── Live vulnerable output ── -->
            <div class="xss-output-section">
                <h4>Live Output (vulnerable single-quoted attribute):</h4>
                <div class="xss-output-box" style="padding:0.5rem 0.75rem;">
                    <!--
                        THIS IS THE ACTUAL VULNERABILITY:
                        The value attribute uses single quotes and $safe_bio is not
                        encoded with ENT_QUOTES — single quotes pass through unescaped.
                    -->
                    <input type='text' name='bio' value='<?= $safe_bio ?>'
                           placeholder='Enter your bio...'
                           style='width:100%; background:var(--surface2); color:var(--text);
                                  border:1px solid var(--border); padding:0.4rem 0.6rem;
                                  border-radius:4px; font-family:inherit;'>
                </div>
                <?php if ($bio !== ''): ?>
                <div style="margin-top:0.75rem; padding:0.6rem 0.9rem; background:var(--bg);
                            border:1px solid var(--border); border-radius:var(--radius); font-size:0.8rem;">
                    <span style="color:var(--text-muted);">$safe_bio value (ENT_COMPAT applied):</span><br>
                    <code style="font-size:0.78rem; color:#f87171; word-break:break-all;">
                        <?= htmlspecialchars($safe_bio) ?>
                    </code>
                    <br>
                    <span style="color:var(--text-muted); margin-top:0.3rem; display:block;">
                        Raw single-quote count in $safe_bio:
                        <strong style="color:#fbbf24;"><?= substr_count($safe_bio, "'") ?></strong>
                        (unchanged by ENT_COMPAT)
                    </span>
                </div>
                <?php endif; ?>
                <p class="xss-sandbox-note">
                    Inspect the page source to see how your <code>'</code> breaks
                    out of the <code>value='...'</code> context and creates new attributes.
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
