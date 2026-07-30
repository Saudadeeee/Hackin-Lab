<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 5;
$levelTitle = 'XInclude File Read';
$prevLevel  = 4;
$nextLevel  = 6;

$sample = "<data>\n  <name>hello</name>\n</data>";

// ── Challenge logic: DOCTYPE is stripped, then XInclude is processed ──
$xmlInput   = $_POST['xml'] ?? '';
$flag       = '';
$output     = null;
$parseError = '';
$sanitized  = '';

if (trim($xmlInput) !== '') {
    // "Security": remove any DOCTYPE so classic entities cannot be declared.
    $sanitized = preg_replace('/<!DOCTYPE[^>]*>/i', '', $xmlInput);

    xxe_register_loader();
    libxml_use_internal_errors(true);
    libxml_clear_errors();

    $dom = new DOMDocument();
    $ok  = @$dom->loadXML($sanitized, LIBXML_NOENT);
    if ($ok) {
        @$dom->xinclude(LIBXML_NOENT);          // ← XInclude resolved here
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
    <title>Level 5 — <?= htmlspecialchars($levelTitle) ?> | XXE Lab</title>
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
        <span class="level-badge">Level 5</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level5.php — strips DOCTYPE, but still runs XInclude</span>
<span class="php-variable">$xml</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'xml'</span>];
<span class="php-comment">// block classic entities by removing the DOCTYPE</span>
<span class="php-variable">$xml</span> = <span class="php-function">preg_replace</span>(<span class="php-string">'/&lt;!DOCTYPE[^&gt;]*&gt;/i'</span>, <span class="php-string">''</span>, <span class="php-variable">$xml</span>);

<span class="php-variable">$dom</span> = <span class="php-keyword">new</span> <span class="php-function">DOMDocument</span>();
<span class="php-variable">$dom</span>-&gt;<span class="php-function">loadXML</span>(<span class="php-variable">$xml</span>, <span class="php-keyword">LIBXML_NOENT</span>);
<span class="vuln-line"><span class="php-variable">$dom</span>-&gt;<span class="php-function">xinclude</span>(<span class="php-keyword">LIBXML_NOENT</span>);   <span class="php-comment">// ← pulls in external resources</span></span>
<span class="php-keyword">echo</span> <span class="php-variable">$dom</span>-&gt;textContent;<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; Stripping <code>&lt;!DOCTYPE&gt;</code> kills entity-based XXE, but
                <code>xinclude()</code> needs no DTD. An <code>&lt;xi:include parse="text" href="file://…"&gt;</code>
                element reads the file anyway. Target <code>/var/secret/flag5.txt</code>.
            </div>
        </div>

        <div class="challenge-panel">
            <div style="padding:1rem;">
                <div class="scenario">
                    <h3>Scenario</h3>
                    <p>This importer sanitizes DOCTYPE declarations, so the developer assumed XXE was impossible.
                    They forgot XInclude. Use the XInclude namespace to read
                    <code>/var/secret/flag5.txt</code>.</p>
                    <p style="margin-top:0.4rem;">Starter XML:</p>
                    <div class="sample-xml"><?= htmlspecialchars($sample) ?></div>
                </div>

                <form method="post" action="level5.php">
                    <div class="form-group">
                        <label class="form-label" for="xml_input">XML Payload</label>
                        <textarea id="xml_input" name="xml" class="form-control" spellcheck="false" autocomplete="off"><?= htmlspecialchars($xmlInput !== '' ? $xmlInput : $sample) ?></textarea>
                    </div>
                    <div style="display:flex; gap:0.6rem; margin-top:0.5rem; flex-wrap:wrap;">
                        <button type="submit" class="btn btn-primary">Import XML</button>
                        <a href="level5.php" class="btn btn-secondary">Reset</a>
                    </div>
                </form>

                <?php if ($output !== null): ?>
                <div style="margin-top:1rem;">
                    <?php if ($sanitized !== $xmlInput): ?>
                    <label class="form-label">After DOCTYPE stripping</label>
                    <div class="output-box"><?= htmlspecialchars(trim((string)$sanitized)) ?></div>
                    <?php endif; ?>
                    <label class="form-label" style="margin-top:0.5rem;">Imported document text</label>
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
                    <p>XInclude pulled the file straight into the document — no DTD required.</p>
                    <code><?= htmlspecialchars($flag) ?></code>
                    <p style="margin-top:0.75rem;"><a href="submit.php" style="color:#818cf8;">Submit this flag &rarr;</a></p>
                </div>
                <?php elseif ($output !== null): ?>
                <div class="message error">Add <code>xmlns:xi="http://www.w3.org/2001/XInclude"</code> and an <code>&lt;xi:include parse="text" href="file:///var/secret/flag5.txt"/&gt;</code> element.</div>
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
