<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 6;
$levelTitle = 'XXE via SVG Upload';
$prevLevel  = 5;
$nextLevel  = 7;

$sample = "<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"200\" height=\"40\">\n  <text x=\"5\" y=\"25\">logo</text>\n</svg>";

// ── Challenge logic: an uploaded SVG (XML) is parsed and its text read ──
$svgSource  = '';
$flag       = '';
$output     = null;
$parseError = '';
$submitted  = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($_POST['_flag_submit'])) {
    $submitted = true;
    if (!empty($_FILES['svg']['tmp_name']) && is_uploaded_file($_FILES['svg']['tmp_name'])) {
        $svgSource = (string)file_get_contents($_FILES['svg']['tmp_name']);
    } elseif (trim($_POST['xml'] ?? '') !== '') {
        $svgSource = (string)$_POST['xml'];
    }
}

if ($svgSource !== '') {
    xxe_register_loader();
    libxml_use_internal_errors(true);
    libxml_clear_errors();

    $dom = new DOMDocument();
    $ok  = @$dom->loadXML($svgSource, LIBXML_NOENT | LIBXML_DTDLOAD);   // ← SVG is XML: entities resolve
    if ($ok) {
        $output = $dom->textContent;                                    // the "rendered" text of the SVG
    } else {
        $errs = libxml_get_errors();
        $parseError = trim(implode("\n", array_map(fn($e) => trim($e->message), $errs)));
        $output = '[SVG parse failed]';
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
    <title>Level 6 — <?= htmlspecialchars($levelTitle) ?> | XXE Lab</title>
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
        <span class="level-badge">Level 6</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level6.php — "avatar" SVG upload handler</span>
<span class="php-variable">$svg</span> = <span class="php-function">file_get_contents</span>(<span class="php-variable">$_FILES</span>[<span class="php-string">'svg'</span>][<span class="php-string">'tmp_name'</span>]);

<span class="php-function">xxe_register_loader</span>();
<span class="php-variable">$dom</span> = <span class="php-keyword">new</span> <span class="php-function">DOMDocument</span>();
<span class="vuln-line"><span class="php-variable">$dom</span>-&gt;<span class="php-function">loadXML</span>(<span class="php-variable">$svg</span>, <span class="php-keyword">LIBXML_NOENT</span> | <span class="php-keyword">LIBXML_DTDLOAD</span>);</span>
<span class="php-comment">// read the &lt;text&gt; nodes to index the image</span>
<span class="php-keyword">echo</span> <span class="php-variable">$dom</span>-&gt;textContent;<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; SVG is XML. The upload handler parses it with entities enabled,
                so a <code>DOCTYPE</code> inside the SVG is honoured. Embed an external entity for
                <code>/var/secret/flag6.txt</code> and reference it in a <code>&lt;text&gt;</code> node.
            </div>
        </div>

        <div class="challenge-panel">
            <div style="padding:1rem;">
                <div class="scenario">
                    <h3>Scenario</h3>
                    <p>An avatar service accepts SVG uploads and reads the text nodes for indexing.
                    Craft a malicious SVG, save it as <code>.svg</code>, and upload it (or paste the markup below).</p>
                    <p style="margin-top:0.4rem;">Base SVG (add a DOCTYPE + entity):</p>
                    <div class="sample-xml"><?= htmlspecialchars($sample) ?></div>
                </div>

                <form method="post" action="level6.php" enctype="multipart/form-data">
                    <div class="form-group">
                        <label class="form-label" for="svg_file">Upload SVG file</label>
                        <input type="file" id="svg_file" name="svg" accept=".svg,image/svg+xml,text/xml" class="form-control">
                    </div>
                    <div class="form-group" style="margin-top:0.5rem;">
                        <label class="form-label" for="xml_input">…or paste SVG markup</label>
                        <textarea id="xml_input" name="xml" class="form-control" spellcheck="false" autocomplete="off" placeholder="&lt;?xml version=&quot;1.0&quot;?&gt;&#10;&lt;!DOCTYPE svg [ ... ]&gt;&#10;&lt;svg ...&gt;&lt;text&gt;&amp;xxe;&lt;/text&gt;&lt;/svg&gt;"><?= htmlspecialchars(!empty($_POST['xml']) ? (string)$_POST['xml'] : '') ?></textarea>
                    </div>
                    <div style="display:flex; gap:0.6rem; margin-top:0.5rem; flex-wrap:wrap;">
                        <button type="submit" class="btn btn-primary">Upload &amp; Parse</button>
                        <a href="level6.php" class="btn btn-secondary">Reset</a>
                    </div>
                </form>

                <?php if ($submitted): ?>
                <div style="margin-top:1rem;">
                    <label class="form-label">Extracted SVG text</label>
                    <div class="output-box <?= trim((string)$output) === '' ? 'empty' : '' ?>"><?= $output === null ? 'No SVG received. Choose a file or paste markup.' : htmlspecialchars((string)$output) ?></div>
                    <?php if ($parseError !== ''): ?>
                    <label class="form-label" style="margin-top:0.5rem;">libxml errors</label>
                    <div class="output-box"><?= htmlspecialchars($parseError) ?></div>
                    <?php endif; ?>
                </div>
                <?php endif; ?>

                <?php if ($flag): ?>
                <div class="flag-display">
                    <h3>&#x1F3C6; Flag Captured!</h3>
                    <p>The uploaded SVG's entity resolved the secret while the image was "indexed".</p>
                    <code><?= htmlspecialchars($flag) ?></code>
                    <p style="margin-top:0.75rem;"><a href="submit.php" style="color:#6f9fb0;">Submit this flag &rarr;</a></p>
                </div>
                <?php elseif ($submitted): ?>
                <div class="message error">Include <code>&lt;!DOCTYPE svg [ &lt;!ENTITY xxe SYSTEM "file:///var/secret/flag6.txt"&gt; ]&gt;</code> and reference <code>&amp;xxe;</code> inside a <code>&lt;text&gt;</code> element.</div>
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
