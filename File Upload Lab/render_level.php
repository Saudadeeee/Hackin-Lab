<?php
/**
 * Shared level renderer for the File Upload Lab.
 *
 * Each levelN.php sets:
 *   $levelId (int), $levelTitle (string), $difficulty (string),
 *   $scenario (html), $vulnNote (html), $sourceCode (html)
 * then `require __DIR__ . '/render_level.php';`
 *
 * This file runs the REAL per-level filter (filter_level{N}), stores whatever
 * survives, and calls verify_upload() to award the flag when an executable PHP
 * payload got through.
 */
require_once __DIR__ . '/helpers.php';

$prevLevel = $levelId - 1;
$nextLevel = $levelId + 1;

$_flag_result = handle_inline_flag_submit($levelId);

$u          = get_upload_input();
$accepted   = null;
$reason     = '';
$storedRel  = null;
$storedName = '';
$flag       = '';
$flagMsg    = '';

if ($u !== null) {
    [$accepted, $reason] = call_user_func('filter_level' . $levelId, $u);
    if ($accepted) {
        $storedRel  = store_upload($levelId, $u['name'], $u['content']);
        $storedName = $u['name'];
    }
    // $storedRel is passed so the gate can request the file back and confirm
    // Apache really executed it, rather than trusting a static look at the bytes.
    if (verify_upload($levelId, $u['name'], $u['content'], $u['mime'], $storedRel)) {
        $flag    = get_flag_for_level($levelId);
        $flagMsg = 'Executable PHP survived the filter — arbitrary code execution achieved!';
    }
}

$hints    = get_level_hints($levelId);
$diffClass = 'difficulty-' . strtolower($difficulty);

// Refill values for the form (escaped).
$fname    = $_POST['fname']    ?? '';
$fcontent = $_POST['fcontent'] ?? '';
$fmime    = $_POST['fmime']    ?? 'application/octet-stream';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level <?= (int)$levelId ?> — <?= htmlspecialchars($levelTitle) ?> | File Upload Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        /* Supplemental styling for the semantic classes used by this lab,
           layered on top of the shared B&W theme tokens. */
        .header-title { font-weight: 600; color: var(--white); font-size: 1rem; letter-spacing: 0.01em; }
        .submit-link {
            padding: 0.35rem 0.85rem; border-radius: 0; text-decoration: none;
            font-size: 0.8rem; font-weight: 600; color: var(--bg); background: var(--white);
            border: 1px solid var(--white); transition: background 0.15s, color 0.15s;
        }
        .submit-link:hover { background: transparent; color: var(--white); }
        .level-header {
            display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;
            margin: 0 0 1.25rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border);
        }
        .level-header h1 { font-size: 1.35rem; font-weight: 700; color: var(--white); letter-spacing: -0.01em; flex: 1 1 auto; }
        .level-badge {
            font-size: 0.72rem; font-weight: 700; color: var(--text-faint); background: var(--surface3);
            border: 1px solid var(--border); padding: 3px 9px; border-radius: 0;
            letter-spacing: 0.08em; text-transform: uppercase;
        }
        .difficulty-badge {
            font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em;
            padding: 3px 9px; border-radius: 0; border: 1px solid var(--border-mid);
        }
        .difficulty-easy   { color: #c3c0b6; border-color: #2f3546; background: #151821; }
        .difficulty-medium { color: #9a978f; border-color: #2f3546; background: #151821; }
        .difficulty-hard   { color: #9a978f; border-color: #2f3546; background: #1a1e28; }
        .difficulty-expert { color: var(--white); border-color: var(--border-hi); background: var(--surface3); }
        .vuln-annotation {
            padding: 0.85rem 1rem; font-size: 0.82rem; color: var(--text-muted); line-height: 1.65;
            border-top: 1px solid var(--border); background: var(--surface);
        }
        .vuln-annotation strong { color: var(--text); }
        .btn-secondary { background: var(--surface2); color: var(--text-muted); border-color: var(--border-mid); }
        .btn-secondary:hover { color: var(--text); border-color: var(--border-hi); }
        .scenario h3 { font-size: 0.8rem; color: var(--text); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.4rem; }
        .challenge-panel > h3, .code-panel > h3 { margin: 0; }
        .file-link {
            display: inline-block; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 0.8rem;
            color: var(--white); border: 1px solid var(--border-hi); border-radius: 0;
            padding: 0.35rem 0.7rem; text-decoration: none; margin-top: 0.35rem; word-break: break-all;
        }
        .file-link:hover { background: var(--surface3); }
        .field-note { font-size: 0.72rem; color: var(--text-faint); margin-top: 0.25rem; }
        textarea.form-control { min-height: 130px; resize: vertical; line-height: 1.5; white-space: pre; }
    </style>
</head>
<body>

<header class="header">
    <a href="index.php" class="back-btn">&larr; Back to Levels</a>
    <div class="header-title"><span style="color:var(--primary)">&#x2B06;</span> File Upload Lab</div>
    <a href="submit.php" class="submit-link">Submit Flag</a>
</header>

<div class="container">

    <div class="level-header">
        <span class="level-badge">Level <?= (int)$levelId ?></span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge <?= $diffClass ?>"><?= htmlspecialchars($difficulty) ?></span>
    </div>

    <div class="challenge-layout">

        <!-- ── Left: Source Code Panel ── -->
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><?= $sourceCode ?></code></pre>
            </div>
            <div class="vuln-annotation"><?= $vulnNote ?></div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">
            <h3>Challenge</h3>
            <div class="panel-body">

                <div class="scenario">
                    <h3>Scenario</h3>
                    <?= $scenario ?>
                </div>

                <form method="POST" action="level<?= (int)$levelId ?>.php" enctype="multipart/form-data">
                    <div class="form-group">
                        <label class="form-label" for="fname">Filename to store</label>
                        <input type="text" id="fname" name="fname" class="form-control"
                               placeholder="e.g. shell.php" autocomplete="off" spellcheck="false"
                               value="<?= htmlspecialchars($fname) ?>">
                        <div class="field-note">Controls the stored extension (try alternate / double / mixed-case extensions).</div>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="fmime">Content-Type (claimed)</label>
                        <input type="text" id="fmime" name="fmime" class="form-control"
                               placeholder="application/octet-stream" autocomplete="off" spellcheck="false"
                               value="<?= htmlspecialchars($fmime) ?>">
                        <div class="field-note">Attacker-controlled MIME header sent with the upload.</div>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="fcontent">File content</label>
                        <textarea id="fcontent" name="fcontent" class="form-control"
                                  placeholder="&lt;?php readfile('/var/secret/level<?= (int)$levelId ?>_flag.txt'); ?&gt;"
                                  spellcheck="false"><?= htmlspecialchars($fcontent) ?></textarea>
                        <div class="field-note">The raw bytes written to disk. Prepend magic bytes or switch PHP tags as needed.</div>
                    </div>
                    <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                        <button type="submit" class="btn btn-primary">Upload</button>
                        <a href="level<?= (int)$levelId ?>.php" class="btn btn-secondary">Clear</a>
                    </div>
                </form>

                <?php if ($u !== null): ?>
                <div style="margin-top:1rem;">
                    <label class="form-label">Server response</label>
                    <div class="message <?= $accepted ? 'success' : 'error' ?>">
                        <?= htmlspecialchars($reason) ?>
                    </div>
                    <?php if ($storedRel !== null): ?>
                    <div class="field-note" style="margin-top:0.5rem;">Stored file (click to request it — a PHP payload will execute):</div>
                    <a class="file-link" href="<?= htmlspecialchars($storedRel) ?>" target="_blank" rel="noopener">
                        <?= htmlspecialchars('uploads/level' . $levelId . '/' . $storedName) ?>
                    </a>
                    <?php endif; ?>
                </div>
                <?php endif; ?>

                <?php if ($flag): ?>
                <div class="message success" style="margin-top:1rem;"><?= htmlspecialchars($flagMsg) ?></div>
                <div class="flag-display"><?= htmlspecialchars($flag) ?></div>
                <p style="font-size:0.82rem; color:var(--text-muted); margin-top:0.5rem;">
                    Submit this flag below (or on <a href="submit.php" style="color:var(--primary);">submit.php</a>) to record your progress.
                </p>
                <?php elseif ($u !== null && $accepted): ?>
                <div class="message info" style="margin-top:0.75rem;">
                    The file passed the filter, but it is not an executable PHP payload yet. Review the hints.
                </div>
                <?php endif; ?>

            </div><!-- /.panel-body -->
        </div><!-- /.challenge-panel -->
    </div><!-- /.challenge-layout -->

    <?= render_hint_section($hints) ?>
    <?= render_inline_flag_form($levelId, $_flag_result) ?>

    <div class="navigation">
        <a href="index.php" class="nav-link">&larr; Home</a>
        <a href="submit.php" class="nav-link">Submit Flag</a>
        <?php if ($nextLevel <= 10): ?>
        <a href="level<?= (int)$nextLevel ?>.php" class="next-link">Level <?= (int)$nextLevel ?> &rarr;</a>
        <?php else: ?>
        <a href="submit.php" class="next-link">Finish &rarr;</a>
        <?php endif; ?>
    </div>

</div><!-- /.container -->
</body>
</html>
