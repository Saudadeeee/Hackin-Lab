<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 6;
$levelTitle = 'Bypass Script Tag Filter';
$prevLevel  = 5;
$nextLevel  = 7;

// ── Challenge logic ──────────────────────────────────────────
$input = $_GET['input'] ?? '';

// Apply the same (broken) filter shown in the source code
$filtered = str_replace('<script>', '', $input);
$filtered = str_replace('</script>', '', $filtered);

$flag        = '';
$flagMessage = '';

if ($input !== '' && verify_xss_payload($levelId, $input)) {
    $flag        = get_flag_for_level($levelId);
    $flagMessage = 'Filter bypass confirmed — XSS payload survives the str_replace!';
}

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 6 — Bypass Script Tag Filter | XSS Lab</title>
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
        <span class="level-badge">Level 6</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">

        <!-- ── Left: Source Code Panel ── -->
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-variable">$input</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'input'</span>] ?? <span class="php-string">''</span>;

<span class="php-comment">// Case-SENSITIVE removal — only lowercase &lt;script&gt;</span>
<span class="vuln-line"><span class="php-variable">$filtered</span> = str_replace(<span class="php-string">'&lt;script&gt;'</span>, <span class="php-string">''</span>, <span class="php-variable">$input</span>);</span><span class="vuln-line"><span class="php-variable">$filtered</span> = str_replace(<span class="php-string">'&lt;/script&gt;'</span>, <span class="php-string">''</span>, <span class="php-variable">$filtered</span>);</span>
<span class="php-keyword">echo</span> <span class="php-string">"&lt;div class='output'&gt;Output: "</span>
   . <span class="php-variable">$filtered</span>
   . <span class="php-string">"&lt;/div&gt;"</span>;</code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp;
                PHP's <code>str_replace</code> is <strong>case-sensitive</strong>. It only removes
                the exact lowercase string <code>&lt;script&gt;</code>. Uppercase variants, mixed
                case, or alternative XSS vectors (e.g., <code>&lt;img onerror=...&gt;</code>) pass
                through completely unfiltered.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>A developer added a "security filter" that removes <code>&lt;script&gt;</code>
                tags before echoing user input. The filter calls
                <code>str_replace('&lt;script&gt;', '', $input)</code> — case-sensitive, one-shot.</p>
                <p>Your task: craft a payload that <strong>survives the filter</strong> and still
                executes JavaScript. The server-side verifier applies the same filter and checks
                whether XSS potential remains.</p>
                <p>Three bypass techniques exist — can you find all of them?</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level6.php">
                <div class="form-group">
                    <label class="form-label" for="input_field">XSS Payload (input parameter)</label>
                    <input
                        type="text"
                        id="input_field"
                        name="input"
                        class="form-control"
                        placeholder='e.g. &lt;SCRIPT&gt;alert(1)&lt;/SCRIPT&gt;'
                        value="<?= htmlspecialchars($input) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Submit Payload</button>
                    <?php if ($input !== ''): ?>
                    <a href="level6.php" class="btn btn-secondary">Clear</a>
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
            <?php elseif ($input !== ''): ?>
            <div class="message error">
                The filter neutralised your payload. Your XSS vector must survive
                the <code>str_replace</code> — try a different capitalisation or
                an entirely different tag.
            </div>
            <?php endif; ?>

            <!-- ── Live filter output ── -->
            <?php if ($input !== ''): ?>
            <div class="xss-output-section">
                <h4>Filter Debug:</h4>
                <div style="background:var(--bg); border:1px solid var(--border); border-radius:var(--radius);
                            padding:0.65rem 0.9rem; font-size:0.82rem; margin-bottom:0.5rem;">
                    <span style="color:var(--text-muted);">Raw input:</span><br>
                    <code style="color:#f87171; word-break:break-all; font-size:0.78rem;">
                        <?= htmlspecialchars($input) ?>
                    </code><br><br>
                    <span style="color:var(--text-muted);">After filter:</span><br>
                    <code style="color:#34d399; word-break:break-all; font-size:0.78rem;">
                        <?= htmlspecialchars($filtered) ?>
                    </code>
                </div>

                <h4>Live Output (filtered result rendered):</h4>
                <div class="xss-output-box">
                    <!--
                        THIS IS THE ACTUAL VULNERABLE OUTPUT:
                        $filtered is echoed raw — if filter bypassed, XSS executes here.
                    -->
                    <div class='output'>Output: <?= $filtered ?></div>
                </div>
                <p class="xss-sandbox-note">
                    The filter result is rendered as raw HTML above. If your bypass succeeds,
                    the payload will execute in your browser.
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
