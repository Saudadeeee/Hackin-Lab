<?php
/**
 * CSRF Lab — Shared white-box level renderer.
 *
 * Produces the exact two-column challenge layout used across the Hackin Lab
 * suite (mirrors XSS Lab/level1.php) so every CSRF level is visually identical.
 * Each level file builds a small config array and calls csrf_render_level().
 */

/**
 * @param array $c {
 *   id, title, difficulty, endpoint, method_label, defense_label, samesite,
 *   source_html, vuln_annotation, scenario_html, console_rows (label=>value),
 *   scaffold, result (array|null), solved (bool), flag (string), hints (array),
 *   flag_form (string), prev (int), next (int)
 * }
 */
function csrf_render_level(array $c): void {
    $id    = (int)$c['id'];
    $title = (string)$c['title'];
    $diff  = (string)$c['difficulty'];
    $diffClass = 'difficulty-' . strtolower($diff);
    $result = $c['result'] ?? null;
    $solved = !empty($c['solved']);
    $flag   = (string)($c['flag'] ?? '');
    $poc    = $result['poc'] ?? ($c['scaffold'] ?? '');
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level <?= $id ?> — <?= htmlspecialchars($title) ?> | CSRF Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .vuln-annotation {
            background: var(--surface2);
            border: 1px solid var(--border);
            border-left: 2px solid var(--border-hi);
            border-radius: 0 6px 6px 0;
            padding: 0.65rem 0.9rem;
            margin: 0.9rem 1rem 1rem;
            font-size: 0.8rem;
            color: var(--text-muted);
            line-height: 1.55;
        }
        .vuln-annotation strong { color: var(--white); }
        .level-header {
            display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;
            padding: 0.5rem 0 1.25rem;
        }
        .level-header h1 { font-size: 1.4rem; font-weight: 700; color: var(--white); }
        .level-badge {
            font-size: 0.72rem; font-weight: 700; color: var(--text-faint);
            background: var(--surface3); border: 1px solid var(--border);
            padding: 2px 8px; border-radius: 0; letter-spacing: 0.08em; text-transform: uppercase;
        }
        .difficulty-badge {
            font-size: 0.65rem; font-weight: 700; text-transform: uppercase;
            letter-spacing: 0.06em; padding: 2px 8px; border-radius: 0; border: 1px solid var(--border-mid);
            color: var(--text-muted);
        }
        .difficulty-expert { color: var(--white); border-color: var(--border-hi); background: var(--surface3); }
        .scenario h3 { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); margin-bottom: 0.4rem; background: none; border: 0; padding: 0; }
        .scenario h3, .scenario p { margin-bottom: 0.4rem; }
        .deliver-form textarea.form-control { min-height: 150px; resize: vertical; line-height: 1.5; white-space: pre; }
        .btn-row { display: flex; gap: 0.6rem; margin-top: 0.6rem; flex-wrap: wrap; }
        .btn-secondary { background: transparent; color: var(--white); border-color: var(--border-hi); }
        .btn-secondary:hover { background: var(--surface3); }
        .console-title { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); margin: 1rem 0 0.4rem; font-weight: 600; }
        .flag-display h3 { color: var(--white); font-size: 0.85rem; background: none; border: 0; padding: 0; margin-bottom: 0.35rem; text-transform: none; letter-spacing: 0; }
        .flag-display code { background: var(--code-bg); border: 1px solid var(--border-hi); color: var(--white); padding: 2px 8px; }
    </style>
</head>
<body>

<header class="header">
    <a href="index.php" class="back-btn">&larr; Back to Levels</a>
    <div class="header-title"><span style="color:var(--primary)">&#x1F6E1;</span> CSRF Lab</div>
    <a href="submit.php" class="submit-btn">Submit Flag</a>
</header>

<div class="container">

    <div class="level-header">
        <span class="level-badge">Level <?= $id ?></span>
        <h1><?= htmlspecialchars($title) ?></h1>
        <span class="difficulty-badge <?= $diffClass ?>"><?= htmlspecialchars($diff) ?></span>
    </div>

    <div class="challenge-layout">

        <!-- ── Left: Source Code Panel ── -->
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><?= $c['source_html'] ?></code></pre>
            </div>
            <div class="vuln-annotation"><?= $c['vuln_annotation'] ?></div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">
            <div style="padding: 1rem;">

                <div class="scenario">
                    <h3>Scenario</h3>
                    <?= $c['scenario_html'] ?>
                </div>

                <div class="context-bar">
                    <span>Endpoint <strong><?= htmlspecialchars($c['endpoint']) ?></strong></span>
                    <span>Method <strong><?= htmlspecialchars($c['method_label']) ?></strong></span>
                    <span>Protection <strong><?= htmlspecialchars($c['defense_label']) ?></strong></span>
                    <span>SameSite <strong><?= htmlspecialchars($c['samesite']) ?></strong></span>
                </div>

                <div class="console-title">&#x1F464; Victim Admin Console (live state)</div>
                <table class="data-table">
                    <?php foreach (($c['console_rows'] ?? []) as $label => $value): ?>
                    <tr>
                        <th style="width:45%;"><?= htmlspecialchars((string)$label) ?></th>
                        <td><?= htmlspecialchars((string)$value) ?></td>
                    </tr>
                    <?php endforeach; ?>
                </table>

                <form method="post" action="visit.php" class="deliver-form" style="margin-top:1rem;">
                    <input type="hidden" name="level" value="<?= $id ?>">
                    <div class="form-group">
                        <label class="form-label" for="poc">Attack PoC (delivered to the logged-in admin)</label>
                        <textarea id="poc" name="poc" class="form-control" spellcheck="false" autocomplete="off"><?= htmlspecialchars($poc) ?></textarea>
                    </div>
                    <div class="btn-row">
                        <button type="submit" class="btn btn-primary">Deliver to victim &rarr;</button>
                        <a href="level<?= $id ?>.php?reset=1" class="btn btn-secondary">Reset victim</a>
                    </div>
                </form>

                <?php if ($result !== null): ?>
                    <?php if (!empty($result['ok'])): ?>
                    <div class="message success" style="margin-top:0.9rem;">
                        <strong>Exploit landed.</strong> <?= htmlspecialchars($result['reason']) ?>
                    </div>
                    <?php else: ?>
                    <div class="message error" style="margin-top:0.9rem;">
                        <strong>Blocked / no change.</strong> <?= htmlspecialchars($result['reason']) ?>
                    </div>
                    <?php endif; ?>
                    <div class="console-title">Request the victim's browser sent</div>
                    <div class="output-box"><?= htmlspecialchars(csrf_request_summary($result['req'], $id)) ?></div>
                <?php endif; ?>

                <?php if ($solved): ?>
                <div class="flag-display" style="margin-top:0.9rem;">
                    <h3>&#x1F3C6; Flag Captured!</h3>
                    <code><?= htmlspecialchars($flag) ?></code>
                    <p style="margin-top:0.6rem; font-size:0.8rem;">
                        <a href="submit.php">Submit this flag &rarr;</a>
                    </p>
                </div>
                <?php endif; ?>

            </div><!-- /padding -->
        </div><!-- /.challenge-panel -->
    </div><!-- /.challenge-layout -->

    <?= render_hint_section($c['hints']) ?>
    <?= $c['flag_form'] ?>

    <div class="navigation">
        <a href="index.php" class="nav-link">&larr; Home</a>
        <a href="submit.php" class="nav-link">Submit Flag</a>
        <?php if ((int)$c['next'] >= 1 && (int)$c['next'] <= 10): ?>
        <a href="level<?= (int)$c['next'] ?>.php" class="next-link">Level <?= (int)$c['next'] ?> &rarr;</a>
        <?php else: ?>
        <a href="submit.php" class="next-link">Finish &rarr;</a>
        <?php endif; ?>
    </div>

</div><!-- /.container -->
</body>
</html>
    <?php
}
