<?php
/**
 * Hackin-Lab Portal · the main menu.
 *
 * Lists every lab grouped by the suggested order, shows which are running, and
 * reads each lab's progress cookie so the whole suite has one scoreboard.
 */
require_once __DIR__ . '/registry.php';

$labs   = portal_labs();
$phases = portal_phases();

/* Clear every lab's progress. Cookies are host-scoped, so one page can do it. */
if (isset($_GET['reset'])) {
    foreach ($labs as $lab) {
        setcookie($lab['cookie'], '', time() - 3600, '/');
    }
    header('Location: index.php?cleared=1');
    exit;
}

$status = portal_status($labs);

$totalLevels = 0;
$totalSolved = 0;
foreach ($labs as &$lab) {
    $lab['solved'] = count(portal_solved($lab['cookie']));
    $lab['live']   = $status[$lab['port']] ?? null;
    $totalLevels  += $lab['levels'];
    $totalSolved  += min($lab['solved'], $lab['levels']);
}
unset($lab);

usort($labs, static fn($a, $b) => $a['order'] <=> $b['order']);

$byPhase = [];
foreach ($labs as $lab) {
    $byPhase[$lab['phase']][] = $lab;
}

$liveCount = count(array_filter($status));
$pct       = $totalLevels ? (int)round($totalSolved / $totalLevels * 100) : 0;

function esc(?string $s): string
{
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Hackin-Lab</title>
<link rel="stylesheet" href="css/styles.css">
<style>
    /* The portal is the desktop these windows sit on. Same Turbo Vision
       language as the labs, one level up. */

    .pt-wrap { max-width: 1120px; margin: 0 auto; }

    /* --- hero: the thesis, beside a real trace ---------------------------- */
    .pt-hero { display: grid; grid-template-columns: 1fr; gap: 1.25rem; margin-bottom: 2rem; }
    @media (min-width: 940px) { .pt-hero { grid-template-columns: 1.05fr 1fr; align-items: start; } }

    .pt-thesis h1 {
        font-family: var(--font-chrome);
        font-size: 1.45rem;
        line-height: 1.5;
        color: var(--amber);
        text-transform: none;
        letter-spacing: 0;
    }
    .pt-thesis h1 em { color: var(--cyan); font-style: normal; }
    .pt-thesis p {
        font-family: var(--font-body);
        color: var(--text-muted);
        font-size: 0.92rem;
        line-height: 1.8;
        margin-top: 0.9rem;
        max-width: 54ch;
    }

    .pt-metrics { display: flex; gap: 1.75rem; flex-wrap: wrap; margin-top: 1.5rem; }
    .pt-metric-value { font-family: var(--font-chrome); font-size: 1.45rem; color: var(--ink); line-height: 1; }
    .pt-metric-value small { color: var(--text-faint); font-size: 0.72em; }
    .pt-metric-label {
        font-family: var(--font-chrome); font-size: 0.56rem; letter-spacing: 0.06em;
        text-transform: uppercase; color: var(--cyan); margin-top: 0.45rem;
    }
    .pt-hero-bar { margin-top: 1.1rem; max-width: 420px; }

    /* --- the sample trace ------------------------------------------------- */
    .pt-sample { margin: 0; }
    .pt-sample-caption {
        font-family: var(--font-body); font-size: 0.78rem; color: var(--text-muted);
        line-height: 1.65; margin-top: 0.85rem; padding-top: 0.75rem;
        border-top: 1px solid var(--border);
    }

    /* --- filter bar ------------------------------------------------------- */
    .pt-filter {
        display: flex; gap: 0.85rem; align-items: center; flex-wrap: wrap;
        background: var(--window);
        border: 1px solid var(--border);
        box-shadow: 4px 4px 0 var(--hardshadow);
        padding: 0.7rem 0.9rem;
        margin-bottom: 2rem;
    }
    .pt-filter input[type=search] { flex: 1; min-width: 240px; }
    .pt-filter label {
        font-family: var(--font-chrome); font-size: 0.6rem; text-transform: uppercase;
        color: var(--cyan); display: flex; align-items: center; gap: 0.4rem; cursor: pointer;
    }
    .pt-filter #pt-count { font-family: var(--font-chrome); font-size: 0.6rem; color: var(--text-faint); }

    /* --- phases ----------------------------------------------------------- */
    .pt-phase { margin-bottom: 2.5rem; }
    .pt-phase[hidden] { display: none; }
    .pt-phase-head {
        display: flex; align-items: center; gap: 0.7rem; flex-wrap: wrap;
        background: var(--chrome); color: var(--ink); padding: 0.35rem 0.7rem;
        box-shadow: inset 1px 1px 0 var(--chrome-hi), inset -1px -1px 0 var(--chrome-lo);
    }
    .pt-phase-num {
        font-family: var(--font-chrome); font-size: 0.58rem; letter-spacing: 0.06em;
        background: var(--chrome-lo); color: var(--amber); padding: 0.16rem 0.42rem;
    }
    .pt-phase-head h2 {
        font-family: var(--font-chrome); font-size: 0.76rem; color: var(--amber);
        text-transform: uppercase; letter-spacing: 0.02em;
    }
    .pt-phase-head .lead { font-family: var(--font-body); font-size: 0.79rem; color: var(--ink-2); }
    .pt-phase-why {
        font-family: var(--font-body); font-size: 0.83rem; color: var(--text-muted);
        line-height: 1.75; margin: 0.9rem 0 1.1rem; max-width: 82ch;
    }

    /* --- lab cards -------------------------------------------------------- */
    .pt-grid { display: grid; gap: 1rem; grid-template-columns: 1fr; }
    @media (min-width: 720px)  { .pt-grid { grid-template-columns: 1fr 1fr; } }
    @media (min-width: 1180px) { .pt-grid { grid-template-columns: 1fr 1fr 1fr; } }

    .pt-card {
        display: flex; flex-direction: column;
        background: var(--window);
        border: 1px solid var(--border);
        box-shadow: 4px 4px 0 var(--hardshadow);
    }
    .pt-card[hidden] { display: none; }
    .pt-card:hover { border-color: var(--amber); }
    .pt-card.pt-done { border-color: #3d5236; }
    .pt-card.pt-offline { opacity: 0.5; }

    .pt-card-top {
        display: flex; align-items: center; gap: 0.5rem;
        background: var(--window-in);
        border-bottom: 1px solid var(--border);
        padding: 0.4rem 0.7rem;
        font-family: var(--font-chrome); font-size: 0.56rem;
        text-transform: uppercase; letter-spacing: 0.03em;
    }
    .pt-dot { width: 8px; height: 8px; flex: 0 0 auto; }
    .pt-dot-up   { background: var(--lime); }
    .pt-dot-down { background: var(--red); }
    .pt-dot-unk  { background: var(--chrome-lo); }
    .pt-state-up   { color: var(--lime); }
    .pt-state-down { color: var(--red); }
    .pt-state-unk  { color: var(--text-faint); }
    .pt-port { margin-left: auto; color: var(--amber); font-family: var(--font-mono); font-size: 0.68rem; }

    .pt-card-body { padding: 0.85rem 0.9rem 0.9rem; display: flex; flex-direction: column; flex: 1; }
    .pt-card h3 {
        font-family: var(--font-chrome); font-size: 0.88rem; color: var(--ink);
        line-height: 1.35; text-transform: none; letter-spacing: 0;
    }
    .pt-class {
        font-family: var(--font-chrome); font-size: 0.54rem; letter-spacing: 0.05em;
        text-transform: uppercase; color: var(--cyan); margin-top: 0.3rem;
    }
    .pt-note {
        font-family: var(--font-body); font-size: 0.8rem; color: var(--text-muted);
        line-height: 1.65; margin: 0.7rem 0 0.9rem; flex: 1;
    }

    .pt-prog { display: flex; align-items: center; gap: 0.55rem; font-family: var(--font-mono); font-size: 0.72rem; }
    .pt-prog b { color: var(--ink); font-weight: 600; min-width: 3.2rem; }
    .pt-prog .pt-bar { flex: 1; }
    .pt-done-tag { font-family: var(--font-chrome); font-size: 0.54rem; color: var(--lime); }

    .pt-links { display: flex; gap: 0.35rem; flex-wrap: wrap; margin-top: 0.85rem; }
    .pt-links a {
        font-family: var(--font-chrome); font-size: 0.56rem; text-transform: uppercase;
        letter-spacing: 0.03em; text-decoration: none; padding: 0.32rem 0.6rem;
        background: var(--chrome); color: var(--ink);
        border: 1px solid var(--border-mid);
        box-shadow: inset 1px 1px 0 var(--chrome-hi);
    }
    .pt-links a:hover { background: var(--chrome-hi); color: var(--amber); text-decoration: none; }
    .pt-links a.primary { color: var(--amber); border-color: var(--amber); }
    .pt-links a.primary:hover { background: rgba(207, 166, 92, 0.16); }

    /* --- method + warning ------------------------------------------------- */
    .pt-method { margin-bottom: 2rem; }
    .pt-method ol {
        margin: 0 0 0 1.3rem; font-family: var(--font-body); font-size: 0.86rem;
        color: var(--text); line-height: 1.85;
    }
    .pt-method li::marker { color: var(--amber); font-family: var(--font-mono); }
    .pt-method li + li { margin-top: 0.25rem; }
    .pt-method strong { color: var(--amber); font-weight: 600; }
    .pt-method p { font-family: var(--font-body); font-size: 0.82rem; color: var(--text-muted); margin-top: 0.85rem; }

    .pt-warn {
        font-family: var(--font-body); font-size: 0.82rem; line-height: 1.7;
        background: var(--window-in); color: var(--ink);
        border: 1px solid var(--border); border-left: 3px solid var(--red);
        box-shadow: 4px 4px 0 var(--hardshadow);
        padding: 0.7rem 0.9rem; margin-bottom: 2rem;
    }
    .pt-warn strong { color: var(--red); }
</style>
</head>
<body>

<header class="header">
    <div class="header-left">
        <h1>&#9776; Hackin-Lab</h1>
        <p><?= count($labs) ?> labs &middot; <?= $totalLevels ?> levels &middot; <?= $liveCount ?> running</p>
    </div>
    <div class="header-right">
        <a href="index.php" class="back-btn">Refresh</a>
        <a href="index.php?reset=1" class="back-btn"
           onclick="return confirm('Clear progress for every lab? This cannot be undone.')">Reset progress</a>
    </div>
</header>

<div class="container pt-wrap">

    <?php if (isset($_GET['cleared'])): ?>
        <div class="message info" style="margin-bottom:1.5rem">Progress cleared for every lab.</div>
    <?php endif; ?>

    <div class="pt-hero">
        <div class="pt-thesis">
            <h1>Read the code.<br>Then read <em>the trace</em>.</h1>
            <p>Every level ships the vulnerable source that is actually running, walks your own input through it one
            stage at a time, and prints the exact string handed to the dangerous operation. Finish a level and you
            should be able to say why it worked without opening a hint.</p>

            <div class="pt-metrics">
                <div>
                    <div class="pt-metric-value"><?= $totalSolved ?><small>/<?= $totalLevels ?></small></div>
                    <div class="pt-metric-label">levels solved</div>
                </div>
                <div>
                    <div class="pt-metric-value"><?= $pct ?><small>%</small></div>
                    <div class="pt-metric-label">complete</div>
                </div>
                <div>
                    <div class="pt-metric-value"><?= $liveCount ?><small>/<?= count($labs) ?></small></div>
                    <div class="pt-metric-label">labs running</div>
                </div>
            </div>
            <div class="pt-bar pt-hero-bar"><div style="width:<?= $pct ?>%"></div></div>
        </div>

        <!-- A real trace from XSS level 6: the filter deletes the lowercase tag,
             and the deletion joins what is left back into a new one. -->
        <div class="lk-box lk-pipeline pt-sample">
            <h4><span class="lk-tag">TRACE</span>What the server did to your input</h4>
            <div class="lk-body">
                <div class="lk-stage">
                    <div class="lk-stage-head"><span class="lk-step">1</span><code>$_GET['input']</code></div>
                    <div class="lk-stage-val">&lt;scr&lt;script&gt;ipt&gt;alert(1)&lt;/scr&lt;/script&gt;ipt&gt;</div>
                </div>
                <div class="lk-stage">
                    <div class="lk-stage-head"><span class="lk-step">2</span><code>str_replace('&lt;script&gt;','',$input)</code>
                        <span class="lk-chip lk-chip-warn">modified</span></div>
                    <div class="lk-stage-val">&lt;scr&lt;ipt&gt;alert(1)&lt;/scr&lt;/script&gt;ipt&gt;</div>
                    <div class="lk-stage-note">Removed 1 occurrence. Deletion can leave a new token behind.</div>
                </div>
                <div class="lk-stage lk-stage-pass">
                    <div class="lk-stage-head"><span class="lk-step">3</span><code>str_replace('&lt;/script&gt;','',$f)</code>
                        <span class="lk-chip lk-chip-good">passed</span></div>
                    <div class="lk-stage-val">&lt;script&gt;alert(1)&lt;/script&gt;</div>
                    <div class="lk-stage-note">One pass, in this order. Neither call runs again after the other modified the string.</div>
                </div>
                <p class="pt-sample-caption">This panel appears on every level, filled with your own payload. A
                blocked attempt names the stage that stopped it, so a failure is as informative as a win.</p>
            </div>
        </div>
    </div>

    <div class="pt-warn">
        <strong>Intentionally vulnerable, for education only.</strong> Keep these on localhost. Do not expose any of
        these ports to a network you do not control.
    </div>

    <div class="lk-box pt-method">
        <h4><span class="lk-tag">METHOD</span>How to work a level</h4>
        <div class="lk-body">
            <ol>
                <li>Read the <strong>source panel</strong> on the left and find where your input lands.</li>
                <li>Read the <strong>mental model</strong>: what is structural in that position, and where a value can break out.</li>
                <li>Run the <strong>probes</strong>. Each answers a single question and is harmless on purpose.</li>
                <li><strong>Predict</strong> what the trace will say, then send your payload and check the prediction.</li>
                <li>On success, read <strong>why it worked</strong> and <strong>the fix</strong>. That is the part that transfers.</li>
            </ol>
            <p>A level takes 15 to 40 minutes if you read rather than guess. The five hints are progressive and hint 5
            is a working payload &mdash; reach for hint 1 when stuck and stop there. A greyed-out lab below is not
            running; start it with <code>./labs.sh up &lt;name&gt;</code>.</p>
        </div>
    </div>

    <div class="pt-filter">
        <input id="pt-q" type="search" class="form-control" placeholder="Filter by name, class or port   (press /)"
               autocomplete="off" spellcheck="false">
        <label><input type="checkbox" id="pt-only-live"> only running</label>
        <span id="pt-count"></span>
    </div>

    <?php foreach ($byPhase as $phaseId => $group):
        $ph = $phases[$phaseId]; ?>
    <section class="pt-phase">
        <div class="pt-phase-head">
            <span class="pt-phase-num">PHASE <?= $phaseId ?></span>
            <h2><?= esc($ph['title']) ?></h2>
            <span class="lead"><?= esc($ph['lead']) ?></span>
        </div>
        <p class="pt-phase-why"><?= esc($ph['why']) ?></p>

        <div class="pt-grid">
            <?php foreach ($group as $lab):
                $base  = 'http://localhost:' . $lab['port'];
                $done  = $lab['solved'] >= $lab['levels'];
                $lpct  = $lab['levels'] ? (int)round(min($lab['solved'], $lab['levels']) / $lab['levels'] * 100) : 0;
                $live  = $lab['live'];
                $dot   = $live === true ? 'up' : ($live === false ? 'down' : 'unk');
                $state = $live === true ? 'running' : ($live === false ? 'stopped' : 'unknown');
            ?>
            <div class="pt-card<?= $done ? ' pt-done' : '' ?><?= $live === false ? ' pt-offline' : '' ?>"
                 data-search="<?= esc(strtolower(strip_tags($lab['name']) . ' ' . $lab['class'] . ' ' . $lab['dir'] . ' ' . $lab['port'])) ?>"
                 data-live="<?= $live ? '1' : '0' ?>">
                <div class="pt-card-top">
                    <span class="pt-dot pt-dot-<?= $dot ?>"></span>
                    <span class="pt-state-<?= $dot ?>"><?= esc($state) ?></span>
                    <span class="pt-port">:<?= $lab['port'] ?></span>
                </div>
                <div class="pt-card-body">
                    <h3><?= $lab['name'] ?></h3>
                    <div class="pt-class"><?= esc($lab['class']) ?> &middot; <?= $lab['levels'] ?> levels</div>
                    <p class="pt-note"><?= $lab['note'] ?></p>

                    <div class="pt-prog">
                        <b><?= min($lab['solved'], $lab['levels']) ?>/<?= $lab['levels'] ?></b>
                        <div class="pt-bar"><div style="width:<?= $lpct ?>%"></div></div>
                        <?php if ($done): ?><span class="pt-done-tag">done</span><?php endif; ?>
                    </div>

                    <div class="pt-links">
                        <a class="primary" href="<?= $base ?>/index.php" target="_blank" rel="noopener">Open</a>
                        <a href="<?= $base ?>/submit.php" target="_blank" rel="noopener">Flags</a>
                        <?php foreach ($lab['tools'] as $label => $path): ?>
                            <a href="<?= $base ?>/<?= esc($path) ?>" target="_blank" rel="noopener"><?= esc($label) ?></a>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </section>
    <?php endforeach; ?>

</div>

<script>
(function () {
    const q      = document.getElementById('pt-q');
    const live   = document.getElementById('pt-only-live');
    const count  = document.getElementById('pt-count');
    const cards  = Array.from(document.querySelectorAll('.pt-card'));
    const phases = Array.from(document.querySelectorAll('.pt-phase'));

    function apply() {
        const term = q.value.trim().toLowerCase();
        let shown = 0;
        cards.forEach(c => {
            const show = (!term || c.dataset.search.includes(term))
                      && (!live.checked || c.dataset.live === '1');
            c.hidden = !show;
            if (show) shown++;
        });
        phases.forEach(p => { p.hidden = !p.querySelector('.pt-card:not([hidden])'); });
        count.textContent = shown + ' / ' + cards.length;
    }

    q.addEventListener('input', apply);
    live.addEventListener('change', apply);
    document.addEventListener('keydown', e => {
        if (e.key === '/' && document.activeElement !== q) { e.preventDefault(); q.focus(); }
        if (e.key === 'Escape' && document.activeElement === q) { q.value = ''; apply(); q.blur(); }
    });
    apply();
})();
</script>
</body>
</html>
