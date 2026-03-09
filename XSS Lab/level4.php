<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 4;
$levelTitle = 'DOM-based XSS via innerHTML';
$prevLevel  = 3;
$nextLevel  = 5;

// ── Server-side flag check ───────────────────────────────────
// PHP reads the same 'msg' param to verify the payload server-side.
// The actual DOM injection happens in the client-side JavaScript below.
$msg = $_GET['msg'] ?? '';

$flag        = '';
$flagMessage = '';

if ($msg !== '' && verify_xss_payload($levelId, $msg)) {
    $flag        = get_flag_for_level($levelId);
    $flagMessage = 'DOM XSS payload confirmed by server-side verifier!';
}

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 4 — DOM-based XSS via innerHTML | XSS Lab</title>
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
        <span class="level-badge">Level 4</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">

        <!-- ── Left: Source Code Panel ── -->
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="js-comment">// Vulnerable client-side JavaScript
// (runs in the browser — server never sees msg)</span>

<span class="js-keyword">const</span> <span class="js-variable">params</span> = <span class="js-keyword">new</span> <span class="js-method">URLSearchParams</span>(<span class="js-property">location</span>.search);
<span class="js-keyword">const</span> <span class="js-variable">msg</span> = <span class="js-variable">params</span>.<span class="js-method">get</span>(<span class="js-string">'msg'</span>) || <span class="js-string">'Welcome!'</span>;
<span class="vuln-line">document.<span class="js-method">getElementById</span>(<span class="js-string">'output'</span>).<span class="js-property">innerHTML</span> = <span class="js-variable">msg</span>;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp;
                <code>innerHTML</code> parses its input as HTML. The <code>msg</code> URL parameter
                goes directly from <code>URLSearchParams</code> into the DOM without any sanitisation.
                The server is never involved — this is pure client-side injection.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>A web page renders a welcome message by reading the <code>msg</code>
                query parameter in JavaScript and assigning it to <code>element.innerHTML</code>.</p>
                <p>The server never processes this parameter. The vulnerability is entirely
                in client-side code. <strong>The JavaScript below actually runs in your
                browser</strong> — your payload will execute live.</p>
                <p>The server-side verifier also checks <code>$_GET['msg']</code> to award the flag
                once a valid XSS vector is detected.</p>
            </div>

            <!-- DOM output target — JS will write here -->
            <div class="xss-output-section">
                <h4>DOM Output (innerHTML target):</h4>
                <div class="xss-output-box">
                    <div id="output">Welcome!</div>
                </div>
                <p class="xss-sandbox-note">
                    This is <strong>live client-side XSS</strong>. Your <code>msg</code> payload is
                    assigned to <code>innerHTML</code> above — it will execute in your browser.
                    Note: <code>&lt;script&gt;</code> tags injected via <code>innerHTML</code>
                    do <em>not</em> run; use event-handler based vectors like
                    <code>&lt;img src=x onerror=...&gt;</code>.
                </p>
            </div>

            <!-- Payload form — updates URL with msg parameter -->
            <form method="get" action="level4.php">
                <div class="form-group">
                    <label class="form-label" for="msg_input">XSS Payload (msg parameter)</label>
                    <input
                        type="text"
                        id="msg_input"
                        name="msg"
                        class="form-control"
                        placeholder='e.g. &lt;img src=x onerror=alert(1)&gt;'
                        value="<?= htmlspecialchars($msg) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Submit Payload</button>
                    <?php if ($msg !== ''): ?>
                    <a href="level4.php" class="btn btn-secondary">Clear</a>
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
            <?php elseif ($msg !== ''): ?>
            <div class="message error">
                Not a recognised XSS vector. Remember: <code>&lt;script&gt;</code> tags injected
                via <code>innerHTML</code> don't execute — try <code>&lt;img&gt;</code> or
                <code>&lt;svg&gt;</code> with an event handler.
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

<!--
    THIS IS THE ACTUAL VULNERABLE JAVASCRIPT.
    It reads the 'msg' URL parameter and assigns it to innerHTML —
    any HTML/JS payload in the URL executes in the browser.
-->
<script>
(function() {
    var params = new URLSearchParams(location.search);
    var msg    = params.get('msg') || 'Welcome!';
    // VULNERABLE: innerHTML parses msg as raw HTML
    document.getElementById('output').innerHTML = msg;
})();
</script>

</body>
</html>
