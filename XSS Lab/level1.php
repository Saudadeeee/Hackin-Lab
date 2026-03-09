<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 1;
$levelTitle = 'Basic Reflected XSS';
$prevLevel  = 0;
$nextLevel  = 2;

// ── Challenge logic ──────────────────────────────────────────
// The vulnerable parameter
$name = $_GET['name'] ?? '';

$flag        = '';
$flagMessage = '';

if ($name !== '' && verify_xss_payload($levelId, $name)) {
    $flag        = get_flag_for_level($levelId);
    $flagMessage = 'XSS payload detected server-side!';
}

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 1 — Basic Reflected XSS | XSS Lab</title>
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
<span class="php-comment">// level1.php — the actual code running this page</span>
<span class="php-variable">$name</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'name'</span>] ?? <span class="php-string">''</span>;
<span class="vuln-line"><span class="php-keyword">echo</span> <span class="php-string">"&lt;div class='greeting'&gt;Hello, "</span> . <span class="php-variable">$name</span> . <span class="php-string">"!&lt;/div&gt;"</span>;</span><span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The <code>$name</code> variable is concatenated raw into the
                HTML string. No <code>htmlspecialchars()</code>, no filtering — whatever you send
                becomes part of the page's DOM.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>You are testing a web application that greets users by name. The developer simply
                echoes the <code>name</code> GET parameter directly into the page output.</p>
                <p>Craft an XSS payload and submit it via the form below. If the server-side
                verifier detects a valid XSS vector in your input, it will award the flag.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level1.php">
                <div class="form-group">
                    <label class="form-label" for="name_input">XSS Payload (name parameter)</label>
                    <input
                        type="text"
                        id="name_input"
                        name="name"
                        class="form-control"
                        placeholder='e.g. &lt;script&gt;alert(1)&lt;/script&gt;'
                        value="<?= htmlspecialchars($name) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Submit Payload</button>
                    <?php if ($name !== ''): ?>
                    <a href="level1.php" class="btn btn-secondary">Clear</a>
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
            <?php elseif ($name !== ''): ?>
            <div class="message error">Not a recognised XSS payload. Try injecting HTML tags or event handlers.</div>
            <?php endif; ?>

            <!-- ── Live vulnerable output (the actual XSS reflection) ── -->
            <?php if ($name !== ''): ?>
            <div class="xss-output-section">
                <h4>Live Output (vulnerable reflection):</h4>
                <div class="xss-output-box">
                    <!-- THIS IS THE ACTUAL VULNERABILITY — $name is echoed raw -->
                    <div class='greeting'>Hello, <?= $name ?>!</div>
                </div>
                <p class="xss-sandbox-note">
                    The raw value of <code>$name</code> is rendered here without any encoding.
                    XSS payloads will execute in your browser.
                </p>
            </div>
            <?php endif; ?>

        </div><!-- /.challenge-panel -->
    </div><!-- /.challenge-layout -->

    <?= render_hint_section($hints) ?>
    <?= render_inline_flag_form($levelId, $_flag_result) ?>

    <div class="navigation">
        <a href="index.php" class="btn btn-secondary">&larr; Home</a>
        <a href="submit.php" class="btn btn-secondary nav-center">Submit Flag</a>
        <a href="level<?= $nextLevel ?>.php" class="btn btn-secondary">Level <?= $nextLevel ?> &rarr;</a>
    </div>

</div><!-- /.container -->
</body>
</html>
