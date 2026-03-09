<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 10;
$levelTitle = 'Multi-Layer XSS Filter Bypass';
$prevLevel  = 9;
$nextLevel  = 0; // last level

// ── Challenge logic ──────────────────────────────────────────
$input = $_GET['payload'] ?? '';

// Apply the exact same filters shown in the source code
$filtered = $input;

// Layer 1: Remove <script> tags — case-insensitive, greedy on content
$filtered = preg_replace('/<script[\s\S]*?<\/script>/i', '', $filtered);

// Layer 2: Remove common event handlers and javascript:
$layer2 = ['onerror=', 'onload=', 'onclick=', 'onfocus=', 'onmouseover=', 'javascript:'];
foreach ($layer2 as $b) {
    $filtered = str_ireplace($b, '', $filtered);
}

// Layer 3: Remove HTML comments
$filtered = preg_replace('/<!--[\s\S]*?-->/', '', $filtered);

$flag        = '';
$flagMessage = '';

if ($input !== '' && verify_xss_payload($levelId, $input)) {
    $flag        = get_flag_for_level($levelId);
    $flagMessage = 'Multi-layer WAF bypassed! Your payload survives all three filter layers.';
}

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 10 — Multi-Layer XSS Filter Bypass | XSS Lab</title>
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
<span class="php-variable">$input</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'payload'</span>] ?? <span class="php-string">''</span>;

<span class="php-comment">// Layer 1: Remove &lt;script&gt; tags (case-insensitive)</span>
<span class="vuln-line"><span class="php-variable">$x</span> = preg_replace(<span class="php-string">'&lt;script[\s\S]*?&lt;\/script&gt;/i'</span>, <span class="php-string">''</span>, <span class="php-variable">$input</span>);</span>
<span class="php-comment">// Layer 2: Remove common XSS event handlers</span>
<span class="php-keyword">foreach</span> ([<span class="php-string">'onerror='</span>,<span class="php-string">'onload='</span>,<span class="php-string">'onclick='</span>,<span class="php-string">'onfocus='</span>,
          <span class="php-string">'onmouseover='</span>,<span class="php-string">'javascript:'</span>] <span class="php-keyword">as</span> <span class="php-variable">$b</span>) {
<span class="vuln-line">    <span class="php-variable">$x</span> = str_ireplace(<span class="php-variable">$b</span>, <span class="php-string">''</span>, <span class="php-variable">$x</span>);</span>}
<span class="php-comment">// Layer 3: Remove HTML comments</span>
<span class="vuln-line"><span class="php-variable">$x</span> = preg_replace(<span class="php-string">'/&lt;!--[\s\S]*?--&gt;/'</span>, <span class="php-string">''</span>, <span class="php-variable">$x</span>);</span>
<span class="php-keyword">echo</span> <span class="php-string">"&lt;div class='output'&gt;"</span> . <span class="php-variable">$x</span> . <span class="php-string">"&lt;/div&gt;"</span>;</code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp;
                Three filter layers remove <code>&lt;script&gt;</code> tags, six specific event handlers,
                and HTML comments. But they cover only a small fraction of HTML's event handler
                surface. Hundreds of valid event attributes — <code>ontoggle=</code>,
                <code>onpointerenter=</code>, <code>onwheel=</code>, <code>oncontextmenu=</code>,
                and many more — are completely unchecked.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>A "WAF" applies three filter layers before echoing user input: it strips
                <code>&lt;script&gt;</code> blocks (case-insensitive), removes six common event
                handlers, and strips HTML comments.</p>
                <p>Your goal: find an XSS vector that <strong>none of the three layers removes</strong>.
                The server-side verifier applies all three layers to your payload and checks
                whether executable XSS potential survives.</p>
                <p>Consider: what HTML elements and event handlers are <em>not covered</em>
                by the filter lists?</p>
            </div>

            <!-- Layer summary -->
            <div style="background:var(--bg); border:1px solid var(--border); border-radius:var(--radius);
                        padding:0.75rem 1rem; font-size:0.82rem;">
                <div style="font-weight:700; color:var(--text-muted); text-transform:uppercase;
                            letter-spacing:0.06em; font-size:0.76rem; margin-bottom:0.5rem;">Filter Coverage</div>
                <div style="display:flex; flex-direction:column; gap:0.3rem;">
                    <div><span style="color:#f87171;">Layer 1:</span> <code>&lt;script ...&gt;...&lt;/script&gt;</code> (any case)</div>
                    <div><span style="color:#f87171;">Layer 2:</span> <code>onerror=</code> <code>onload=</code> <code>onclick=</code> <code>onfocus=</code> <code>onmouseover=</code> <code>javascript:</code></div>
                    <div><span style="color:#f87171;">Layer 3:</span> <code>&lt;!-- ... --&gt;</code> HTML comments</div>
                    <div style="margin-top:0.35rem; color:#34d399;"><strong>Not covered:</strong> hundreds of other event handlers, SVG events, HTML5 element-specific events...</div>
                </div>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level10.php">
                <div class="form-group">
                    <label class="form-label" for="payload_input">XSS Payload (payload parameter)</label>
                    <input
                        type="text"
                        id="payload_input"
                        name="payload"
                        class="form-control"
                        placeholder='e.g. &lt;details ontoggle=alert(1) open&gt;'
                        value="<?= htmlspecialchars($input) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Submit Payload</button>
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
            <?php elseif ($input !== ''): ?>
            <div class="message error">
                The filters neutralised your payload. Study the event handler blacklist in
                Layer 2 — find one that is absent from it.
            </div>
            <?php endif; ?>

            <!-- ── Filter trace + live output ── -->
            <?php if ($input !== ''): ?>
            <div class="xss-output-section">
                <h4>Filter Trace:</h4>
                <div style="background:var(--bg); border:1px solid var(--border); border-radius:var(--radius);
                            padding:0.65rem 0.9rem; font-size:0.78rem; margin-bottom:0.5rem;">
                    <div style="color:var(--text-muted);">Raw input:</div>
                    <code style="color:#f87171; word-break:break-all;"><?= htmlspecialchars($input) ?></code>
                    <div style="color:var(--text-muted); margin-top:0.5rem;">After all 3 layers:</div>
                    <code style="color:#34d399; word-break:break-all;"><?= htmlspecialchars($filtered) ?></code>
                    <?php if ($input === $filtered): ?>
                    <div style="color:#fbbf24; margin-top:0.3rem; font-weight:600;">
                        No changes — payload survived all filters.
                    </div>
                    <?php else: ?>
                    <div style="color:var(--danger); margin-top:0.3rem;">
                        Payload was modified by the filters.
                    </div>
                    <?php endif; ?>
                </div>

                <h4>Live Output (filtered result rendered):</h4>
                <div class="xss-output-box">
                    <!--
                        ACTUAL VULNERABLE OUTPUT:
                        $filtered is echoed as raw HTML. If your payload survived all
                        three layers, any event handlers in it execute here.
                    -->
                    <div class='output'><?= $filtered ?></div>
                </div>
                <p class="xss-sandbox-note">
                    The filtered string is rendered as raw HTML. If your bypass is correct,
                    the unlisted event handler fires in your browser above.
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
        <a href="submit.php" class="btn btn-success">&#x1F3C6; Submit Flags &rarr;</a>
    </div>

</div><!-- /.container -->
</body>
</html>
