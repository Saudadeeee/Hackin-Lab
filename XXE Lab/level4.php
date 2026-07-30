<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 4;
$levelTitle = 'Error-Based XXE';
$prevLevel  = 3;
$nextLevel  = 5;

$sample = "<?xml version=\"1.0\"?>\n<config>\n  <mode>strict</mode>\n</config>";

// ── Challenge logic (parser errors are surfaced to the user) ──
$xmlInput   = $_POST['xml'] ?? '';
$flag       = '';
$submitted  = false;
$errorText  = '';

if (trim($xmlInput) !== '') {
    $submitted = true;
    xxe_register_loader();
    libxml_use_internal_errors(true);
    libxml_clear_errors();

    $dom = new DOMDocument();
    @$dom->loadXML($xmlInput, LIBXML_NOENT | LIBXML_DTDLOAD);   // ← entities resolved here

    $errs = libxml_get_errors();                                 // ← errors shown to the user
    $errorText = trim(implode("\n", array_map(fn($e) => trim($e->message), $errs)));
    libxml_clear_errors();

    if (xxe_error_contains_flag($errs, get_flag_for_level($levelId))) {
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
    <title>Level 4 — <?= htmlspecialchars($levelTitle) ?> | XXE Lab</title>
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
        <span class="level-badge">Level 4</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level4.php — verbose parser, prints libxml errors</span>
<span class="php-variable">$xml</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'xml'</span>];

<span class="php-function">xxe_register_loader</span>();
<span class="php-function">libxml_use_internal_errors</span>(<span class="php-keyword">true</span>);

<span class="php-variable">$dom</span> = <span class="php-keyword">new</span> <span class="php-function">DOMDocument</span>();
<span class="vuln-line">@<span class="php-variable">$dom</span>-&gt;<span class="php-function">loadXML</span>(<span class="php-variable">$xml</span>, <span class="php-keyword">LIBXML_NOENT</span> | <span class="php-keyword">LIBXML_DTDLOAD</span>);</span>

<span class="php-keyword">foreach</span> (<span class="php-function">libxml_get_errors</span>() <span class="php-keyword">as</span> <span class="php-variable">$e</span>)
    <span class="php-keyword">echo</span> <span class="php-variable">$e</span>-&gt;message;   <span class="php-comment">// leaks the failing URI</span><span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The parsed content is not echoed, but <em>error messages</em> are.
                Include the hosted DTD at <code>http://127.0.0.1/error.dtd</code>: it reads
                <code>/var/secret/flag4.txt</code> into a parameter entity, then forces libxml to open an invalid URI
                built from it — so the file content lands in the "Invalid URI" error.
            </div>
        </div>

        <div class="challenge-panel">
            <div style="padding:1rem;">
                <div class="scenario">
                    <h3>Scenario</h3>
                    <p>A strict XML validator hides parsed output but dumps parser errors for debugging.
                    Turn a parser error into an exfiltration channel using the hosted
                    <code>error.dtd</code>.</p>
                    <p style="margin-top:0.4rem;">Starter XML:</p>
                    <div class="sample-xml"><?= htmlspecialchars($sample) ?></div>
                </div>

                <form method="post" action="level4.php">
                    <div class="form-group">
                        <label class="form-label" for="xml_input">XML Payload</label>
                        <textarea id="xml_input" name="xml" class="form-control" spellcheck="false" autocomplete="off"><?= htmlspecialchars($xmlInput !== '' ? $xmlInput : $sample) ?></textarea>
                    </div>
                    <div style="display:flex; gap:0.6rem; margin-top:0.5rem; flex-wrap:wrap;">
                        <button type="submit" class="btn btn-primary">Validate XML</button>
                        <a href="level4.php" class="btn btn-secondary">Reset</a>
                    </div>
                </form>

                <?php if ($submitted): ?>
                <div style="margin-top:1rem;">
                    <label class="form-label">Parser errors</label>
                    <div class="output-box <?= $errorText === '' ? 'empty' : '' ?>"><?= $errorText === '' ? 'No parser errors — the document was well-formed.' : htmlspecialchars($errorText) ?></div>
                </div>
                <?php endif; ?>

                <?php if ($flag): ?>
                <div class="flag-display">
                    <h3>&#x1F3C6; Flag Captured!</h3>
                    <p>libxml failed to open a URI built from the secret file — leaking it in the error.</p>
                    <code><?= htmlspecialchars($flag) ?></code>
                    <p style="margin-top:0.75rem;"><a href="submit.php" style="color:#818cf8;">Submit this flag &rarr;</a></p>
                </div>
                <?php elseif ($submitted): ?>
                <div class="message error">No leak yet. Pull in <code>http://127.0.0.1/error.dtd</code> via a parameter entity (<code>%remote;</code>) so the failing load surfaces the flag.</div>
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
