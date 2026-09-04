<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 2;
$levelTitle = 'php://filter Source Read';
$prevLevel  = 1;
$nextLevel  = 3;

$sample = "<?xml version=\"1.0\"?>\n<order>\n  <item>widget</item>\n</order>";

// ── Challenge logic (the REAL vulnerable sink) ───────────────
$xmlInput   = $_POST['xml'] ?? '';
$flag       = '';
$output     = null;
$decoded    = null;
$parseError = '';

if (trim($xmlInput) !== '') {
    xxe_register_loader();
    libxml_use_internal_errors(true);
    libxml_clear_errors();

    $dom = new DOMDocument();
    $ok  = @$dom->loadXML($xmlInput, LIBXML_NOENT | LIBXML_DTDLOAD);   // ← entities resolved here

    if ($ok) {
        $output = $dom->textContent;
        $try    = base64_decode(trim((string)$output), true);
        if ($try !== false && $try !== '') $decoded = $try;
    } else {
        $errs = libxml_get_errors();
        $parseError = trim(implode("\n", array_map(fn($e) => trim($e->message), $errs)));
        $output = '[XML parse failed]';
    }
    libxml_clear_errors();

    if (xxe_contains_flag($output, get_flag_for_level($levelId))) {
        $flag = get_flag_for_level($levelId);
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
    <title>Level 2 — <?= htmlspecialchars($levelTitle) ?> | XXE Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>

<header class="header">
    <a href="index.php" class="back-btn">&larr; Back to Levels</a>
    <div class="header-title"><span style="color:var(--primary)">&#x1F5CE;</span> XXE Lab</div>
    <a href="submit.php" class="submit-link">Submit Flag</a>
</header>

<div class="container">

    <div class="level-header">
        <span class="level-badge">Level 2</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-easy">Easy</span>
    </div>

    <div class="challenge-layout">
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level2.php — parses the submitted XML</span>
<span class="php-variable">$xml</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'xml'</span>];

<span class="php-function">xxe_register_loader</span>();   <span class="php-comment">// file://, php://, http:// all resolve</span>

<span class="php-variable">$dom</span> = <span class="php-keyword">new</span> <span class="php-function">DOMDocument</span>();
<span class="vuln-line"><span class="php-variable">$dom</span>-&gt;<span class="php-function">loadXML</span>(<span class="php-variable">$xml</span>, <span class="php-keyword">LIBXML_NOENT</span> | <span class="php-keyword">LIBXML_DTDLOAD</span>);</span>
<span class="php-keyword">echo</span> <span class="php-variable">$dom</span>-&gt;textContent;<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; Same entity-enabled sink as Level 1 — but this time the
                secret is a PHP file (<code>/var/secret/flag2.php</code>). A raw <code>file://</code> read
                injects <code>&lt;?php</code> markup and the flag never reaches the text. Read it through
                <code>php://filter/convert.base64-encode</code> instead.
            </div>
        </div>

        <div class="challenge-panel">
            <div style="padding:1rem;">
                <div class="scenario">
                    <h3>Scenario</h3>
                    <p>The endpoint echoes parsed text. Your target is a PHP config file at
                    <code>/var/secret/flag2.php</code>. Wrap it in a stream filter so the source survives XML parsing,
                    then base64-decode the result.</p>
                    <p style="margin-top:0.4rem;">Starter XML:</p>
                    <div class="sample-xml"><?= htmlspecialchars($sample) ?></div>
                </div>

                <form method="post" action="level2.php">
                    <div class="form-group">
                        <label class="form-label" for="xml_input">XML Payload</label>
                        <textarea id="xml_input" name="xml" class="form-control" spellcheck="false" autocomplete="off"><?= htmlspecialchars($xmlInput !== '' ? $xmlInput : $sample) ?></textarea>
                    </div>
                    <div style="display:flex; gap:0.6rem; margin-top:0.5rem; flex-wrap:wrap;">
                        <button type="submit" class="btn btn-primary">Parse XML</button>
                        <a href="level2.php" class="btn btn-secondary">Reset</a>
                    </div>
                </form>

                <?php if ($output !== null): ?>
                <div style="margin-top:1rem;">
                    <label class="form-label">Parsed text (raw entity output)</label>
                    <div class="output-box <?= trim((string)$output) === '' ? 'empty' : '' ?>"><?= htmlspecialchars((string)$output) ?></div>
                    <?php if ($decoded !== null): ?>
                    <label class="form-label" style="margin-top:0.5rem;">base64-decoded</label>
                    <div class="output-box"><?= htmlspecialchars((string)$decoded) ?></div>
                    <?php endif; ?>
                    <?php if ($parseError !== ''): ?>
                    <label class="form-label" style="margin-top:0.5rem;">libxml errors</label>
                    <div class="output-box"><?= htmlspecialchars($parseError) ?></div>
                    <?php endif; ?>
                </div>
                <?php endif; ?>

                <?php if ($flag): ?>
                <div class="flag-display">
                    <h3>&#x1F3C6; Flag Captured!</h3>
                    <p>The php://filter wrapper exfiltrated the PHP source; its base64 decodes to the flag.</p>
                    <code><?= htmlspecialchars($flag) ?></code>
                    <p style="margin-top:0.75rem;"><a href="submit.php" style="color:#6f9fb0;">Submit this flag &rarr;</a></p>
                </div>
                <?php elseif ($output !== null): ?>
                <div class="message error">Not there yet. Use <code>php://filter/convert.base64-encode/resource=/var/secret/flag2.php</code> as the entity target.</div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <?= render_hint_section($hints) ?>
    <?= render_inline_flag_form($levelId, $_flag_result) ?>

    <div class="navigation">
        <a href="level<?= $prevLevel ?>.php" class="btn btn-secondary">&larr; Level <?= $prevLevel ?></a>
        <a href="submit.php" class="btn btn-secondary nav-center">Submit Flag</a>
        <a href="level<?= $nextLevel ?>.php" class="btn btn-secondary">Level <?= $nextLevel ?> &rarr;</a>
    </div>

</div>
</body>
</html>
