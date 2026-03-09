<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 7;
$levelTitle = 'XSS via href Attribute (javascript:)';
$prevLevel  = 6;
$nextLevel  = 8;

// ── Challenge logic ──────────────────────────────────────────
$url = $_GET['url'] ?? '#';

$flag        = '';
$flagMessage = '';

if ($url !== '#' && $url !== '' && verify_xss_payload($levelId, $url)) {
    $flag        = get_flag_for_level($levelId);
    $flagMessage = 'javascript: URI vector confirmed! Remember to click the rendered link too.';
}

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 7 — XSS via href Attribute | XSS Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .user-link {
            display: inline-block;
            background: var(--primary);
            color: #fff;
            padding: 0.5rem 1.1rem;
            border-radius: var(--radius);
            font-weight: 600;
            text-decoration: none;
            transition: background 0.2s;
        }
        .user-link:hover { background: var(--primary-hover); color: #fff; text-decoration: none; }
    </style>
</head>
<body>

<header class="header">
    <a href="index.php" class="back-btn">&larr; Back to Levels</a>
    <div class="header-title"><span style="color:var(--primary)">&#x26A1;</span> XSS Lab</div>
    <a href="submit.php" class="submit-link">Submit Flag</a>
</header>

<div class="container">

    <div class="level-header">
        <span class="level-badge">Level 7</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-hard">Hard</span>
    </div>

    <div class="challenge-layout">

        <!-- ── Left: Source Code Panel ── -->
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-variable">$url</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'url'</span>] ?? <span class="php-string">'#'</span>;
<span class="php-keyword">?&gt;</span>

<span class="php-comment">&lt;!-- No URL scheme validation whatsoever --&gt;</span>
<span class="vuln-line">&lt;a href=<span class="php-string">"&lt;?= $url ?&gt;"</span> class=<span class="php-string">"user-link"</span>&gt;Visit Profile&lt;/a&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp;
                The <code>$url</code> parameter is placed directly inside the <code>href</code>
                attribute with no encoding and no URL scheme validation. Browsers honour the
                <code>javascript:</code> pseudo-protocol in <code>href</code> — clicking the
                rendered link executes the JavaScript payload.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>A user profile page renders a "Visit Profile" link using a URL from the
                <code>url</code> GET parameter. The URL is placed directly in the
                <code>href</code> attribute — no <code>htmlspecialchars()</code>, no scheme
                whitelist, no validation.</p>
                <p>Browsers support the <code>javascript:</code> URI scheme in links. When a
                user clicks a link with <code>href="javascript:code"</code>, the browser
                executes that code.</p>
                <p>Submit a <code>javascript:</code> payload. The server will verify it and show
                the flag. Then <strong>click the rendered link</strong> to trigger client-side
                execution.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level7.php">
                <div class="form-group">
                    <label class="form-label" for="url_input">URL Payload (url parameter)</label>
                    <input
                        type="text"
                        id="url_input"
                        name="url"
                        class="form-control"
                        placeholder="e.g. javascript:alert(1)"
                        value="<?= htmlspecialchars($url === '#' ? '' : $url) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Submit Payload</button>
                    <?php if ($url !== '#' && $url !== ''): ?>
                    <a href="level7.php" class="btn btn-secondary">Clear</a>
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
            <?php elseif ($url !== '#' && $url !== ''): ?>
            <div class="message error">
                Payload not accepted. The <code>javascript:</code> scheme must be present
                in your URL value for the verifier to award the flag.
            </div>
            <?php endif; ?>

            <!-- ── Live vulnerable link output ── -->
            <div class="xss-output-section">
                <h4>Live Output (vulnerable href rendering):</h4>
                <div class="xss-output-box" style="display:flex; align-items:center; gap:1rem; flex-wrap:wrap;">
                    <!--
                        THIS IS THE ACTUAL VULNERABILITY:
                        $url is placed directly in href — no encoding, no validation.
                        javascript: URIs execute on click.
                    -->
                    <a href="<?= $url ?>" class="user-link">Visit Profile</a>
                    <?php if ($url !== '#' && $url !== ''): ?>
                    <span style="font-size:0.8rem; color:var(--text-muted);">
                        href value: <code style="color:#f87171;"><?= htmlspecialchars($url) ?></code>
                    </span>
                    <?php endif; ?>
                </div>
                <p class="xss-sandbox-note">
                    The link above uses your <code>url</code> value directly as the
                    <code>href</code>. If you used <code>javascript:alert(1)</code>, clicking
                    the link will execute the JavaScript. Right-click &rarr; "Inspect" to
                    see the raw attribute value in the DOM.
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
