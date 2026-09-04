<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 10;
$levelTitle = 'Multi-Layer Filter Bypass';
$prevLevel  = 9;
$nextLevel  = 0; // last level

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
    <title>Level 10 — Multi-Layer Filter Bypass | Open Redirect Lab</title>
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
        <span class="level-badge">Level 10</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-expert">Expert</span>
    </div>

    <div class="challenge-layout">

        <!-- ── Left: Source Code Panel ── -->
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-variable">$next</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'next'</span>] ?? <span class="php-string">'/'</span>;
<span class="php-variable">$s</span> = trim(<span class="php-variable">$next</span>);
<span class="php-comment">// Layer 1: no protocol-relative</span>
<span class="php-keyword">if</span> (str_starts_with(<span class="php-variable">$s</span>, <span class="php-string">'//'</span>))                        <span class="php-keyword">die</span>(<span class="php-string">'blocked'</span>);
<span class="php-comment">// Layer 2: no backslashes</span>
<span class="php-keyword">if</span> (str_contains(<span class="php-variable">$s</span>, <span class="php-string">'\\'</span>))                         <span class="php-keyword">die</span>(<span class="php-string">'blocked'</span>);
<span class="php-comment">// Layer 3: no dangerous schemes</span>
<span class="php-keyword">if</span> (preg_match(<span class="php-string">'/^(javascript|data|vbscript):/i'</span>, <span class="php-variable">$s</span>)) <span class="php-keyword">die</span>(<span class="php-string">'blocked'</span>);
<span class="php-comment">// Layer 4: no percent-encoding</span>
<span class="php-keyword">if</span> (str_contains(<span class="php-variable">$s</span>, <span class="php-string">'%'</span>))                          <span class="php-keyword">die</span>(<span class="php-string">'blocked'</span>);
<span class="php-comment">// Layer 5: parse_url host allowlist</span>
<span class="php-variable">$host</span> = parse_url(<span class="php-variable">$s</span>, PHP_URL_HOST);
<span class="php-keyword">if</span> (<span class="php-variable">$host</span> === <span class="php-keyword">null</span> || <span class="php-variable">$host</span> === <span class="php-string">'example-bank.local'</span>
    || str_ends_with(<span class="php-variable">$host</span>, <span class="php-string">'.example-bank.local'</span>)) {
<span class="vuln-line">    header(<span class="php-string">"Location: "</span> . <span class="php-variable">$s</span>);   <span class="php-comment">// parse_url('https:/evil')===null</span></span>
}<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; Five layers kill every earlier trick — protocol-relative,
                backslashes, dangerous schemes, and percent-encoding — then a <code>parse_url()</code> host allowlist.
                The gap: the allowlist trusts a <code>null</code> host as "relative", but
                <code>parse_url()</code> only recognises an authority after <code>//</code>. Browsers accept a
                <em>single</em>-slash scheme and normalise it to a full URL.
            </div>
            <div class="lk-box"><h4><span class="lk-tag">PROOF</span>See the real header</h4>
                <div class="lk-body">
                    <p>The level page models the redirect instead of performing it, because a genuine 302 would
                    navigate you away before you could read the trace. <code>go.php</code> runs this same filter and,
                    when it accepts, really does call <code>header('Location: ...')</code>:</p>
                    <pre class="lk-sinkline">curl -i "http://localhost:8092/go.php?level=10&amp;next=&lt;your value&gt;"</pre>
                    <p class="text-muted">A rejected value returns 400 with no <code>Location</code> at all.</p>
                </div>
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>The final endpoint stacks five filters. Everything you used in levels 2–8 is now blocked.</p>
                <p>Find the one form of absolute URL that contains no <code>//</code>, no <code>\</code>, no dangerous
                scheme, and no <code>%</code> — yet <code>parse_url()</code> reads as hostless while the browser sends
                the victim to <code>evil.attacker.example</code>.</p>
            </div>

            <!-- Filter summary -->
            <div style="background:var(--bg); border:1px solid var(--border); border-radius:var(--radius);
                        padding:0.75rem 1rem; font-size:0.82rem;">
                <div style="font-weight:700; color:var(--text-muted); text-transform:uppercase;
                            letter-spacing:0.06em; font-size:0.76rem; margin-bottom:0.5rem;">Filter Coverage</div>
                <div style="display:flex; flex-direction:column; gap:0.3rem;">
                    <div><span style="color:#b5766e;">Layer 1:</span> leading <code>//</code> (protocol-relative)</div>
                    <div><span style="color:#b5766e;">Layer 2:</span> any <code>\</code> backslash</div>
                    <div><span style="color:#b5766e;">Layer 3:</span> <code>javascript:</code> <code>data:</code> <code>vbscript:</code></div>
                    <div><span style="color:#b5766e;">Layer 4:</span> any <code>%</code> (percent-encoding)</div>
                    <div><span style="color:#b5766e;">Layer 5:</span> <code>parse_url()</code> host must be null or <code>*.example-bank.local</code></div>
                    <div style="margin-top:0.35rem; color:#7fa06d;"><strong>Gap:</strong> browsers normalise <code>scheme:/host</code> (one slash) into <code>scheme://host</code>; <code>parse_url()</code> does not.</div>
                </div>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level10.php" style="margin-top:0.85rem;">
                <div class="form-group">
                    <label class="form-label" for="next_input">Redirect target (next parameter)</label>
                    <input
                        type="text"
                        id="next_input"
                        name="next"
                        class="form-control"
                        placeholder="e.g. https:/evil.attacker.example/login"
                        value="<?= htmlspecialchars($input) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Test Redirect</button>
                    <?php if ($input !== ''): ?>
                    <a href="level10.php" class="btn btn-secondary">Clear</a>
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
                A layer blocked it, or it stayed on-site. Reread Layer 5 — how many slashes does
                <code>parse_url()</code> require before it sees a host?
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
        <a href="submit.php" class="btn btn-success">&#x1F3C6; Submit Flags &rarr;</a>
    </div>

</div><!-- /.container -->
</body>
</html>
