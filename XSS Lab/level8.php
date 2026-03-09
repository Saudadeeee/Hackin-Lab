<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 8;
$levelTitle = 'XSS via JSON API Response';
$prevLevel  = 7;
$nextLevel  = 9;

// ── API mode: return JSON ─────────────────────────────────────
// When ?_api=1 is present the page acts as a JSON endpoint.
// The client-side JS fetches this endpoint with the user's message.
if (isset($_GET['_api'])) {
    $msg = $_GET['message'] ?? 'Hello World';
    header('Content-Type: application/json');
    // Intentionally NO htmlspecialchars — the vulnerability lives here and in the client
    echo json_encode(['status' => 'ok', 'message' => $msg]);
    exit;
}

// ── Page mode ─────────────────────────────────────────────────
$message = $_GET['message'] ?? '';

$flag        = '';
$flagMessage = '';

if ($message !== '' && verify_xss_payload($levelId, $message)) {
    $flag        = get_flag_for_level($levelId);
    $flagMessage = 'JSON → innerHTML XSS vector confirmed server-side!';
}

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 8 — XSS via JSON API Response | XSS Lab</title>
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
        <span class="level-badge">Level 8</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-hard">Hard</span>
    </div>

    <div class="challenge-layout">

        <!-- ── Left: Source Code Panel ── -->
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-comment">// ── Server (this endpoint, ?_api=1) ──────────────</span>
<span class="php-keyword">&lt;?php</span>
header(<span class="php-string">'Content-Type: application/json'</span>);
<span class="php-variable">$msg</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'message'</span>] ?? <span class="php-string">'Hello World'</span>;
<span class="php-comment">// No htmlspecialchars — raw value in JSON</span>
<span class="php-keyword">echo</span> json_encode([<span class="php-string">'status'</span> =&gt; <span class="php-string">'ok'</span>, <span class="php-string">'message'</span> =&gt; <span class="php-variable">$msg</span>]);
<span class="php-keyword">?&gt;</span>

<span class="js-comment">// ── Client (vulnerable rendering) ────────────────</span>
fetch(<span class="js-string">'level8.php?_api=1&amp;message='</span> + userInput)
  .<span class="js-method">then</span>(r =&gt; r.<span class="js-method">json</span>())
  .<span class="js-method">then</span>(data =&gt; {
<span class="vuln-line">    document.<span class="js-method">getElementById</span>(<span class="js-string">'result'</span>).<span class="js-property">innerHTML</span> = data.message;</span>  });</code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp;
                The PHP server embeds <code>$msg</code> into JSON without HTML-encoding.
                The client-side JavaScript fetches the JSON and assigns
                <code>data.message</code> directly to <code>innerHTML</code>. JSON encoding
                does <em>not</em> prevent HTML injection — the raw tags survive the round-trip.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>An application fetches a message from a JSON API and renders it using
                <code>element.innerHTML = data.message</code>. Developers often assume that
                because data travels through JSON, it is somehow "sanitised". It is not.</p>
                <p>The PHP endpoint returns your <code>message</code> parameter verbatim inside
                a JSON string. The client decodes the JSON and injects
                <code>data.message</code> as raw HTML.</p>
                <p>Enter a payload below. The page fetches
                <code>level8.php?_api=1&amp;message=YOUR_PAYLOAD</code> via JavaScript and
                renders the response in the output box. The server also checks your payload
                directly for the flag.</p>
            </div>

            <!-- Payload input form - triggers JS fetch on submit -->
            <div class="form-group">
                <label class="form-label" for="msg_input">XSS Payload (message parameter)</label>
                <input
                    type="text"
                    id="msg_input"
                    class="form-control"
                    placeholder='e.g. &lt;img src=x onerror=alert(1)&gt;'
                    value="<?= htmlspecialchars($message) ?>"
                    autocomplete="off"
                    spellcheck="false"
                >
            </div>
            <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                <button type="button" id="fetch-btn" class="btn btn-primary">Fetch &amp; Render</button>
                <a href="level8.php?message=<?= urlencode($message) ?>" class="btn btn-secondary">Submit for Flag Check</a>
                <?php if ($message !== ''): ?>
                <a href="level8.php" class="btn btn-secondary">Clear</a>
                <?php endif; ?>
            </div>

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
            <?php elseif ($message !== ''): ?>
            <div class="message error">
                Not a recognised XSS vector. The <code>message</code> parameter must contain
                HTML tags or event handlers to earn the flag.
            </div>
            <?php endif; ?>

            <!-- ── Live JSON → innerHTML output ── -->
            <div class="xss-output-section">
                <h4>API Response &rarr; innerHTML Result:</h4>
                <div class="xss-output-box" id="api-status" style="min-height:2.5rem; color:var(--text-muted); font-size:0.85rem; font-style:italic;">
                    Enter a payload and click "Fetch &amp; Render"...
                </div>
                <div class="xss-output-box" id="result" style="margin-top:0.5rem; min-height:2rem;">
                </div>
                <div id="raw-json" style="margin-top:0.5rem; padding:0.5rem 0.75rem; background:var(--bg);
                     border:1px solid var(--border); border-radius:var(--radius); font-size:0.78rem; display:none;">
                    <span style="color:var(--text-muted);">Raw JSON response:</span><br>
                    <code id="json-display" style="color:#c3e88d; word-break:break-all; font-size:0.75rem;"></code>
                </div>
                <p class="xss-sandbox-note">
                    "Fetch &amp; Render" calls the API via JavaScript and injects
                    <code>data.message</code> into the box above using <code>innerHTML</code>
                    — your payload executes live. "Submit for Flag Check" sends the payload
                    to PHP for server-side verification.
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

<script>
document.getElementById('fetch-btn').addEventListener('click', function() {
    var userInput  = document.getElementById('msg_input').value;
    var statusBox  = document.getElementById('api-status');
    var resultBox  = document.getElementById('result');
    var rawBox     = document.getElementById('raw-json');
    var jsonDisplay= document.getElementById('json-display');

    if (!userInput) {
        statusBox.textContent = 'Please enter a payload first.';
        statusBox.style.color = 'var(--warning)';
        return;
    }

    statusBox.textContent = 'Fetching from API...';
    statusBox.style.color = 'var(--text-muted)';
    statusBox.style.fontStyle = 'italic';

    // Fetch the JSON endpoint
    fetch('level8.php?_api=1&message=' + encodeURIComponent(userInput))
        .then(function(r) { return r.json(); })
        .then(function(data) {
            statusBox.textContent = 'API response received. data.message injected via innerHTML:';
            statusBox.style.color = 'var(--success)';
            statusBox.style.fontStyle = 'normal';

            // Show raw JSON
            rawBox.style.display = 'block';
            jsonDisplay.textContent = JSON.stringify(data);

            // VULNERABLE: inject data.message directly into innerHTML
            resultBox.innerHTML = data.message;

            // Also update the URL for the server-side flag check link
            var flagLink = document.querySelector('a[href^="level8.php?message="]');
            if (flagLink) {
                flagLink.href = 'level8.php?message=' + encodeURIComponent(userInput);
            }
        })
        .catch(function(err) {
            statusBox.textContent = 'Fetch error: ' + err.message;
            statusBox.style.color = 'var(--danger)';
        });
});

// Pre-populate fetch result if message param is already set
<?php if ($message !== ''): ?>
(function() {
    var preloaded = <?= json_encode($message) ?>;
    document.getElementById('msg_input').value = preloaded;
})();
<?php endif; ?>
</script>

</body>
</html>
