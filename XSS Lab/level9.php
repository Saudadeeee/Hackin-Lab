<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 9;
$levelTitle = 'Bypass XSS Blacklist';
$prevLevel  = 8;
$nextLevel  = 10;

$xss_input = $_GET['xss'] ?? '';

// ── Apply the actual blacklist (as shown in source code) ─────
// If input matches any blacklisted string, terminate with error page.
$blacklist = ['<script', 'javascript:', 'onload=', 'onclick='];
$blocked   = false;
$blockedBy = '';

if ($xss_input !== '') {
    foreach ($blacklist as $bad) {
        if (stripos($xss_input, $bad) !== false) {
            $blocked   = true;
            $blockedBy = $bad;
            break;
        }
    }
}

// If blocked, die() with styled error — just like the actual vulnerable code would
if ($blocked) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>XSS Detected — Level 9 | XSS Lab</title>
        <link rel="stylesheet" href="css/styles.css">
    </head>
    <body>
    <header class="header">
        <a href="index.php" class="back-btn">&larr; Back to Levels</a>
        <div class="header-title"><span style="color:var(--primary)">&#x26A1;</span> XSS Lab</div>
        <a href="submit.php" class="submit-link">Submit Flag</a>
    </header>
    <div class="container" style="max-width:640px;">
        <div class="message error" style="margin-top:2rem; font-size:1rem; padding:1.25rem 1.5rem;">
            <div>
                <strong>XSS detected! Nice try.</strong><br>
                <span style="font-size:0.88rem; margin-top:0.4rem; display:block;">
                    Your payload contained the blacklisted string:
                    <code><?= htmlspecialchars($blockedBy) ?></code>
                </span>
                <span style="font-size:0.85rem; margin-top:0.6rem; display:block; color:var(--text-muted);">
                    This is exactly what the PHP <code>die()</code> would output.
                    The blacklist only blocks four strings — think about what it misses.
                </span>
            </div>
        </div>
        <div style="margin-top:1.25rem; display:flex; gap:0.75rem;">
            <a href="level9.php" class="btn btn-primary">&larr; Try Again</a>
            <a href="index.php" class="btn btn-secondary">Home</a>
        </div>
    </div>
    </body>
    </html>
    <?php
    exit;
}

// ── Not blocked — check for XSS flag award ───────────────────
$flag        = '';
$flagMessage = '';

if ($xss_input !== '' && verify_xss_payload($levelId, $xss_input)) {
    $flag        = get_flag_for_level($levelId);
    $flagMessage = 'Blacklist bypassed! XSS vector confirmed server-side.';
}

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 9 — Bypass XSS Blacklist | XSS Lab</title>
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
        <span class="level-badge">Level 9</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-hard">Hard</span>
    </div>

    <div class="challenge-layout">

        <!-- ── Left: Source Code Panel ── -->
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-variable">$input</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'xss'</span>] ?? <span class="php-string">''</span>;

<span class="php-comment">// Incomplete blacklist — only 4 strings checked</span>
<span class="vuln-line"><span class="php-variable">$blacklist</span> = [<span class="php-string">'&lt;script'</span>, <span class="php-string">'javascript:'</span>, <span class="php-string">'onload='</span>, <span class="php-string">'onclick='</span>];</span>
<span class="php-keyword">foreach</span> (<span class="php-variable">$blacklist</span> <span class="php-keyword">as</span> <span class="php-variable">$bad</span>) {
    <span class="php-keyword">if</span> (stripos(<span class="php-variable">$input</span>, <span class="php-variable">$bad</span>) !== <span class="php-keyword">false</span>) {
        <span class="php-keyword">die</span>(<span class="php-string">"&lt;p class='error'&gt;XSS detected! Nice try.&lt;/p&gt;"</span>);
    }
}
<span class="php-keyword">echo</span> <span class="php-string">"&lt;div class='output'&gt;"</span> . <span class="php-variable">$input</span> . <span class="php-string">"&lt;/div&gt;"</span>;</code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp;
                The blacklist only checks for four strings. HTML supports <strong>hundreds</strong>
                of event handler attributes. Any handler not on the list (e.g., <code>onerror=</code>,
                <code>onmouseover=</code>, <code>onfocus=</code>) passes through and is echoed raw.
                The <code>die()</code> is <em>real</em> — send a blacklisted payload and the page terminates.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>A developer tried to prevent XSS by blocking four common patterns:
                <code>&lt;script</code>, <code>javascript:</code>, <code>onload=</code>,
                and <code>onclick=</code>. The check uses <code>stripos</code>
                (case-insensitive) and calls <code>die()</code> if matched.</p>
                <p>Your payload must <strong>pass the blacklist check</strong> (otherwise
                the page literally dies and shows an error) <strong>and</strong> still carry
                a valid XSS vector. The flag is awarded when both conditions are met.</p>
                <p>Think: which event handlers are <em>not</em> on the list?</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level9.php">
                <div class="form-group">
                    <label class="form-label" for="xss_input">XSS Payload (xss parameter)</label>
                    <input
                        type="text"
                        id="xss_input"
                        name="xss"
                        class="form-control"
                        placeholder='e.g. &lt;img src=x onerror=alert(1)&gt;'
                        value="<?= htmlspecialchars($xss_input) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Submit Payload</button>
                    <?php if ($xss_input !== ''): ?>
                    <a href="level9.php" class="btn btn-secondary">Clear</a>
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
            <?php elseif ($xss_input !== ''): ?>
            <div class="message error">
                Payload passed the blacklist but no XSS vector was detected.
                Your bypass needs an unlisted event handler or tag, not just
                any arbitrary input.
            </div>
            <?php endif; ?>

            <!-- ── Live output (actual XSS — blacklist already passed at this point) ── -->
            <?php if ($xss_input !== ''): ?>
            <div class="xss-output-section">
                <h4>Live Output (echoed after blacklist passed):</h4>
                <div class="xss-output-box">
                    <!--
                        ACTUAL VULNERABLE OUTPUT:
                        $xss_input passed the blacklist and is echoed raw here.
                        If a valid XSS event handler was used, it executes in the browser.
                    -->
                    <div class='output'><?= $xss_input ?></div>
                </div>
                <p class="xss-sandbox-note">
                    Your input passed all four blacklist checks and is rendered as raw HTML.
                    XSS event handlers that are not blacklisted execute here.
                </p>
            </div>
            <?php endif; ?>

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
