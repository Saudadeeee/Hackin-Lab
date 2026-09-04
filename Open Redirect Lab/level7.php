<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 7;
$levelTitle = 'Encoded Slash Bypass';
$prevLevel  = 6;
$nextLevel  = 8;

// ── Challenge logic ──────────────────────────────────────────
$input = $_GET['next'] ?? '';

$vr          = verify_redirect($levelId, $input);
$flag        = $vr['captured'] ? get_flag_for_level($levelId) : '';
$flagMessage = $vr['message'];

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 7 — Encoded Slash Bypass | Open Redirect Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>

<header class="header">
    <a href="index.php" class="back-btn">&larr; Back to Levels</a>
    <div class="header-title"><span style="color:var(--primary)">&#x21AA;</span> Open Redirect Lab</div>
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
<span class="php-variable">$next</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'next'</span>] ?? <span class="php-string">'/'</span>;  <span class="php-comment">// PHP decoded the query string once already</span>
<span class="php-comment">// Reject anything that leaves the site</span>
<span class="php-keyword">if</span> (str_starts_with(<span class="php-variable">$next</span>, <span class="php-string">'//'</span>) || preg_match(<span class="php-string">'#^https?://#i'</span>, <span class="php-variable">$next</span>)) {
    http_response_code(<span class="php-string">400</span>); <span class="php-keyword">echo</span> <span class="php-string">"blocked"</span>; <span class="php-keyword">exit</span>;
}
<span class="vuln-line"><span class="php-variable">$dest</span> = urldecode(<span class="php-variable">$next</span>);          <span class="php-comment">// decode AFTER the check</span></span>
header(<span class="php-string">"Location: "</span> . <span class="php-variable">$dest</span>);   <span class="php-comment">// '%2f%2fevil' -&gt; '//evil'</span><span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The dangerous-prefix check runs against the <em>raw</em> value,
                but the value is <code>urldecode()</code>d <strong>after</strong> the check and before the redirect.
                Percent-encoding the slashes hides them from the filter; decoding restores the protocol-relative URL. Note that <code>$_GET</code> arrives already decoded once, so the payload needs a second encoding layer to still look encoded when the filter inspects it.
            </div>
            <div class="lk-box"><h4><span class="lk-tag">PROOF</span>See the real header</h4>
                <div class="lk-body">
                    <p>The level page models the redirect instead of performing it, because a genuine 302 would
                    navigate you away before you could read the trace. <code>go.php</code> runs this same filter and,
                    when it accepts, really does call <code>header('Location: ...')</code>:</p>
                    <pre class="lk-sinkline">curl -i "http://localhost:8092/go.php?level=7&amp;next=&lt;your value&gt;"</pre>
                    <p class="text-muted">A rejected value returns 400 with no <code>Location</code> at all.</p>
                </div>
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>The filter rejects raw <code>//</code> and <code>http(s)://</code>. But look closely: the value is
                decoded <em>after</em> the check.</p>
                <p>Encode your payload so it passes the raw check, then decodes into a protocol-relative URL pointing
                at <code>evil.attacker.example</code>. Count your decodes: the query string is decoded once on the way in, and <code>urldecode()</code> decodes it again.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level7.php">
                <div class="form-group">
                    <label class="form-label" for="next_input">Redirect target (next parameter)</label>
                    <input
                        type="text"
                        id="next_input"
                        name="next"
                        class="form-control"
                        placeholder="e.g. %2f%2fevil.attacker.example"
                        value="<?= htmlspecialchars($input) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Test Redirect</button>
                    <?php if ($input !== ''): ?>
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
            <?php elseif ($vr['submitted']): ?>
            <div class="message error">
                Blocked or still on-site. What is the percent-encoding of a forward slash &mdash; and how many times is your value decoded before it reaches the redirect?
            </div>
            <?php endif; ?>

            <?= render_redirect_result($vr) ?>

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
