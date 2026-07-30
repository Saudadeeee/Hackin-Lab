<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 6;
$levelTitle = 'Scheme Abuse: file://';
$prevLevel  = 5;
$nextLevel  = 7;

// ── Challenge logic ──────────────────────────────────────────
$url = $_GET['url'] ?? '';

$flag        = '';
$flagMessage = '';
$response    = '';
$fetchError  = '';

if ($url !== '') {
    // The scheme is never validated — file:// reads straight off disk.
    $ctx = stream_context_create(['http' => ['timeout' => 4, 'ignore_errors' => true]]);
    $response = @file_get_contents($url, false, $ctx);
    if ($response === false) {
        $response   = '';
        $fetchError = 'Could not read that resource.';
    }
    if (ssrf_captured($levelId, $response)) {
        $flag        = get_flag_for_level($levelId);
        $flagMessage = 'You abused the file:// wrapper to read a secret off the server filesystem.';
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
    <title>Level 6 — Scheme Abuse: file:// | SSRF Lab</title>
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
<span class="php-variable">$url</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'url'</span>] ?? <span class="php-string">''</span>;

<span class="php-comment">// The scheme is never checked — any wrapper is accepted</span>
<span class="php-variable">$ctx</span> = stream_context_create([<span class="php-string">'http'</span> =&gt; [<span class="php-string">'timeout'</span> =&gt; <span class="php-string">4</span>]]);
<span class="vuln-line"><span class="php-variable">$response</span> = file_get_contents(<span class="php-variable">$url</span>, <span class="php-keyword">false</span>, <span class="php-variable">$ctx</span>);</span>
<span class="php-keyword">echo</span> <span class="php-variable">$response</span>;

<span class="php-comment">// file_get_contents supports file:// — so file:///etc/...</span>
<span class="php-comment">// and file:///var/secret/flag6.txt are all readable.</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The fetcher assumes <code>http</code>, but never
                enforces it. PHP's <code>file://</code> stream wrapper turns the SSRF into an arbitrary
                local file read — including files outside the web root.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>An "import from URL" feature reads whatever URL you provide. It was built for
                <code>http://</code> links, but no one restricted the scheme.</p>
                <p>A secret sits at <code>/var/secret/flag6.txt</code> — outside the web root, so it's
                unreachable over HTTP. Read it anyway using a non-HTTP scheme.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level6.php">
                <div class="form-group">
                    <label class="form-label" for="url_input">Resource URL</label>
                    <input
                        type="text"
                        id="url_input"
                        name="url"
                        class="form-control"
                        placeholder="file:///var/secret/flag6.txt"
                        value="<?= htmlspecialchars($url) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Read Resource</button>
                    <?php if ($url !== ''): ?>
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
            <?php elseif ($url !== '' && $fetchError): ?>
            <div class="message error"><?= htmlspecialchars($fetchError) ?></div>
            <?php elseif ($url !== ''): ?>
            <div class="message info">Read succeeded, but that resource didn't contain the flag. The secret is at <code>/var/secret/flag6.txt</code>.</div>
            <?php endif; ?>

            <!-- ── Server-side fetch result ── -->
            <?php if ($url !== ''): ?>
            <div class="ssrf-output-section">
                <h4 style="margin:0.85rem 0 0.4rem; font-size:0.8rem; color:var(--text-muted);">Resource contents:</h4>
                <div class="output-box <?= $response === '' ? 'empty' : '' ?>"><?= $response === '' ? 'No content read.' : htmlspecialchars(substr($response, 0, 4000)) ?></div>
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
