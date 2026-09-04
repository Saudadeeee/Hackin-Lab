<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 3;
$levelTitle = 'Blind XXE (Out-of-Band)';
$prevLevel  = 2;
$nextLevel  = 4;

$sample = "<?xml version=\"1.0\"?>\n<note>\n  <to>ops</to>\n  <body>status check</body>\n</note>";

// ── Challenge logic (blind sink — response never reflects entities) ──
$xmlInput   = $_POST['xml'] ?? '';
$flag       = '';
$submitted  = false;
$parseError = '';
$callback   = null;

if (trim($xmlInput) !== '') {
    $submitted = true;
    xxe_register_loader();
    libxml_use_internal_errors(true);
    libxml_clear_errors();

    $dom = new DOMDocument();
    // Parsed for "validation" only — the document text is discarded (blind).
    @$dom->loadXML($xmlInput, LIBXML_NOENT | LIBXML_DTDLOAD);

    $errs = libxml_get_errors();
    $parseError = trim(implode("\n", array_map(fn($e) => trim($e->message), $errs)));
    libxml_clear_errors();

    // Confirm server-side whether the out-of-band collector caught the secret.
    $callback = xxe_collector_recent_hit(get_flag_for_level($levelId), 120);
    if ($callback !== null) {
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
    <title>Level 3 — <?= htmlspecialchars($levelTitle) ?> | XXE Lab</title>
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
        <span class="level-badge">Level 3</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level3.php — validates the XML, returns nothing useful</span>
<span class="php-variable">$xml</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'xml'</span>];

<span class="php-function">xxe_register_loader</span>();

<span class="php-variable">$dom</span> = <span class="php-keyword">new</span> <span class="php-function">DOMDocument</span>();
<span class="vuln-line">@<span class="php-variable">$dom</span>-&gt;<span class="php-function">loadXML</span>(<span class="php-variable">$xml</span>, <span class="php-keyword">LIBXML_NOENT</span> | <span class="php-keyword">LIBXML_DTDLOAD</span>);</span>

<span class="php-comment">// NOTE: the parsed document is discarded — nothing is echoed back.</span>
<span class="php-keyword">echo</span> <span class="php-string">"Document received."</span>;<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; Entities still resolve, but the response never contains them —
                this is <em>blind</em> XXE. Exfiltrate the secret out-of-band: pull in the hosted DTD at
                <code>http://127.0.0.1/oob.dtd</code>, which ships <code>/var/secret/flag3.txt</code> to
                <code>collector.php</code>. This page then confirms the callback server-side.
            </div>
        </div>

        <div class="challenge-panel">
            <div style="padding:1rem;">
                <div class="scenario">
                    <h3>Scenario</h3>
                    <p>A webhook validator accepts XML and replies only <code>"Document received."</code>.
                    Nothing is reflected, so you must make the parser call home. An internal collector is
                    listening at <code>http://127.0.0.1/collector.php</code>.</p>
                    <p style="margin-top:0.4rem;">Starter XML (turn it into an external-DTD loader):</p>
                    <div class="sample-xml"><?= htmlspecialchars($sample) ?></div>
                </div>

                <form method="post" action="level3.php">
                    <div class="form-group">
                        <label class="form-label" for="xml_input">XML Payload</label>
                        <textarea id="xml_input" name="xml" class="form-control" spellcheck="false" autocomplete="off"><?= htmlspecialchars($xmlInput !== '' ? $xmlInput : $sample) ?></textarea>
                    </div>
                    <div style="display:flex; gap:0.6rem; margin-top:0.5rem; flex-wrap:wrap;">
                        <button type="submit" class="btn btn-primary">Send Document</button>
                        <a href="level3.php" class="btn btn-secondary">Reset</a>
                    </div>
                </form>

                <?php if ($submitted): ?>
                <div style="margin-top:1rem;">
                    <label class="form-label">Server response</label>
                    <div class="output-box">Document received.</div>
                    <label class="form-label" style="margin-top:0.5rem;">Out-of-band monitor (collector.php)</label>
                    <div class="output-box <?= $callback === null ? 'empty' : '' ?>"><?php
                        if ($callback !== null) {
                            echo 'Callback captured at ' . htmlspecialchars(date('H:i:s', (int)$callback['time'])) . "\n";
                            echo 'raw     : ' . htmlspecialchars((string)$callback['raw']) . "\n";
                            echo 'decoded : ' . htmlspecialchars((string)$callback['decoded']);
                        } else {
                            echo 'No out-of-band callback received in the last 120s. The parser never reached the collector.';
                        }
                    ?></div>
                    <?php if ($parseError !== ''): ?>
                    <label class="form-label" style="margin-top:0.5rem;">libxml notes</label>
                    <div class="output-box"><?= htmlspecialchars($parseError) ?></div>
                    <?php endif; ?>
                </div>
                <?php endif; ?>

                <?php if ($flag): ?>
                <div class="flag-display">
                    <h3>&#x1F3C6; Flag Captured!</h3>
                    <p>The collector received an out-of-band callback carrying the secret file.</p>
                    <code><?= htmlspecialchars($flag) ?></code>
                    <p style="margin-top:0.75rem;"><a href="submit.php" style="color:#6f9fb0;">Submit this flag &rarr;</a></p>
                </div>
                <?php elseif ($submitted): ?>
                <div class="message error">No callback yet. Reference <code>http://127.0.0.1/oob.dtd</code> as an external parameter entity (<code>%remote;</code>) so the parser fetches and executes it.</div>
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
