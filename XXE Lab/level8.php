<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 8;
$levelTitle = 'Parameter-Entity Chaining';
$prevLevel  = 7;
$nextLevel  = 9;

$sample = "<?xml version=\"1.0\"?>\n<root>\n  <msg>hi</msg>\n</root>";

// ── Challenge logic: general entity built by a chain of parameter entities ──
$xmlInput   = $_POST['xml'] ?? '';
$flag       = '';
$output     = null;
$parseError = '';

if (trim($xmlInput) !== '') {
    xxe_register_loader();
    libxml_use_internal_errors(true);
    libxml_clear_errors();

    $dom = new DOMDocument();
    $ok  = @$dom->loadXML($xmlInput, LIBXML_NOENT | LIBXML_DTDLOAD);   // ← param-entity chain resolves
    if ($ok) {
        $output = $dom->textContent;
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
    <title>Level 8 — <?= htmlspecialchars($levelTitle) ?> | XXE Lab</title>
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
        <span class="level-badge">Level 8</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-hard">Hard</span>
    </div>

    <div class="challenge-layout">
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level8.php — full DTD processing enabled</span>
<span class="php-variable">$xml</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'xml'</span>];

<span class="php-function">xxe_register_loader</span>();
<span class="php-variable">$dom</span> = <span class="php-keyword">new</span> <span class="php-function">DOMDocument</span>();
<span class="vuln-line"><span class="php-variable">$dom</span>-&gt;<span class="php-function">loadXML</span>(<span class="php-variable">$xml</span>, <span class="php-keyword">LIBXML_NOENT</span> | <span class="php-keyword">LIBXML_DTDLOAD</span>);</span>
<span class="php-keyword">echo</span> <span class="php-variable">$dom</span>-&gt;textContent;<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The internal subset forbids nesting parameter entities inside
                declarations, so the chain lives in an <em>external</em> DTD hosted at
                <code>http://127.0.0.1/chain.dtd</code>. It chains <code>%f1 &rarr; %f2 &rarr; %build</code> to
                define a general entity <code>&amp;chained;</code> carrying <code>/var/secret/flag8.txt</code>.
            </div>
        </div>

        <div class="challenge-panel">
            <div style="padding:1rem;">
                <div class="scenario">
                    <h3>Scenario</h3>
                    <p>The DTD you need is already hosted at <code>http://127.0.0.1/chain.dtd</code>. Pull it in with
                    a parameter entity and then reference the general entity it builds
                    (<code>&amp;chained;</code>) in the body.</p>
                    <p style="margin-top:0.4rem;">Starter XML:</p>
                    <div class="sample-xml"><?= htmlspecialchars($sample) ?></div>
                </div>

                <form method="post" action="level8.php">
                    <div class="form-group">
                        <label class="form-label" for="xml_input">XML Payload</label>
                        <textarea id="xml_input" name="xml" class="form-control" spellcheck="false" autocomplete="off"><?= htmlspecialchars($xmlInput !== '' ? $xmlInput : $sample) ?></textarea>
                    </div>
                    <div style="display:flex; gap:0.6rem; margin-top:0.5rem; flex-wrap:wrap;">
                        <button type="submit" class="btn btn-primary">Parse XML</button>
                        <a href="level8.php" class="btn btn-secondary">Reset</a>
                    </div>
                </form>

                <?php if ($output !== null): ?>
                <div style="margin-top:1rem;">
                    <label class="form-label">Parsed document text</label>
                    <div class="output-box <?= trim((string)$output) === '' ? 'empty' : '' ?>"><?= htmlspecialchars((string)$output) ?></div>
                    <?php if ($parseError !== ''): ?>
                    <label class="form-label" style="margin-top:0.5rem;">libxml errors</label>
                    <div class="output-box"><?= htmlspecialchars($parseError) ?></div>
                    <?php endif; ?>
                </div>
                <?php endif; ?>

                <?php if ($flag): ?>
                <div class="flag-display">
                    <h3>&#x1F3C6; Flag Captured!</h3>
                    <p>Chained parameter entities assembled a general entity that reflected the file.</p>
                    <code><?= htmlspecialchars($flag) ?></code>
                    <p style="margin-top:0.75rem;"><a href="submit.php" style="color:#818cf8;">Submit this flag &rarr;</a></p>
                </div>
                <?php elseif ($output !== null): ?>
                <div class="message error">Declare <code>&lt;!ENTITY % remote SYSTEM "http://127.0.0.1/chain.dtd"&gt;</code>, invoke <code>%remote;</code>, then put <code>&amp;chained;</code> in the body.</div>
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
