<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 1;
$levelTitle = 'Basic SSRF';
$prevLevel  = 0;
$nextLevel  = 2;

// ── Challenge logic (the REAL vulnerable fetcher) ────────────
$url = $_GET['url'] ?? '';

$flag        = '';
$flagMessage = '';
$response    = '';
$fetchError  = '';

if ($url !== '') {
    // No validation whatsoever on the target URL — this is the SSRF sink.
    $ctx = stream_context_create(['http' => ['timeout' => 4, 'ignore_errors' => true]]);
    $response = @file_get_contents($url, false, $ctx);
    if ($response === false) {
        $response   = '';
        $fetchError = 'The request failed (host unreachable, timed out, or refused).';
    }
    // Flag is awarded only if the fetched response actually contains the
    // internal flag — i.e. the server truly reached the internal resource.
    if (ssrf_captured($levelId, $response)) {
        $flag        = get_flag_for_level($levelId);
        $flagMessage = 'Your SSRF reached the internal endpoint and pulled back its secret.';
    }
}

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 1 — Basic SSRF | SSRF Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>

<header class="header">
    <a href="index.php" class="back-btn">&larr; Back to Levels</a>
    <div class="header-title"><span style="color:var(--primary)">&#x1F310;</span> SSRF Lab</div>
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
<span class="php-variable">$url</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'url'</span>] ?? <span class="php-string">''</span>;

<span class="php-comment">// NO validation on the target — fetch whatever is asked for</span>
<span class="php-variable">$ctx</span> = stream_context_create([<span class="php-string">'http'</span> =&gt; [<span class="php-string">'timeout'</span> =&gt; <span class="php-string">4</span>]]);
<span class="vuln-line"><span class="php-variable">$response</span> = file_get_contents(<span class="php-variable">$url</span>, <span class="php-keyword">false</span>, <span class="php-variable">$ctx</span>);</span>
<span class="php-keyword">echo</span> <span class="php-variable">$response</span>;  <span class="php-comment">// the response is shown back to you</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The user-controlled <code>$url</code> is passed
                straight to <code>file_get_contents()</code>. The server will fetch <em>any</em>
                address — including internal ones your browser cannot reach — and hand you the response.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>This "URL preview" tool fetches whatever address you give it and echoes the
                response. There is an internal page, <code>internal.php</code>, that only answers
                requests coming from <code>127.0.0.1</code> — so you can't open it yourself.</p>
                <p>Make the <strong>server</strong> request it for you. If the response the server
                brings back contains the internal flag, the level is solved.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level1.php">
                <div class="form-group">
                    <label class="form-label" for="url_input">Target URL</label>
                    <input
                        type="text"
                        id="url_input"
                        name="url"
                        class="form-control"
                        placeholder="http://127.0.0.1/internal.php?level=1"
                        value="<?= htmlspecialchars($url) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Fetch URL</button>
                    <?php if ($url !== ''): ?>
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
            <?php elseif ($url !== '' && $fetchError): ?>
            <div class="message error"><?= htmlspecialchars($fetchError) ?></div>
            <?php elseif ($url !== ''): ?>
            <div class="message info">The server fetched that URL, but the response did not contain the internal flag. Aim at the internal endpoint.</div>
            <?php endif; ?>

            <!-- ── Server-side fetch result ── -->
            <?php if ($url !== ''): ?>
            <div class="ssrf-output-section">
                <h4 style="margin:0.85rem 0 0.4rem; font-size:0.8rem; color:var(--text-muted);">Server-side response:</h4>
                <div class="output-box <?= $response === '' ? 'empty' : '' ?>"><?= $response === '' ? 'No response body.' : htmlspecialchars(substr($response, 0, 4000)) ?></div>
                <p style="font-size:0.75rem; color:var(--text-faint); margin-top:0.4rem;">
                    This is exactly what <code>file_get_contents(<?= htmlspecialchars(substr($url,0,80)) ?>)</code>
                    returned to the <em>server</em>.
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
