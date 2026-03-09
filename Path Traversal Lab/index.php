<?php
require_once __DIR__ . '/helpers.php';

$levels    = get_level_info();
$progress  = get_progress();
$completed = count($progress);
$total     = count($levels);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Path Traversal Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
<div class="container">

    <div class="hero">
        <h2>Path Traversal / LFI Lab</h2>
        <p>
            A <strong>white-box</strong> web security training platform. Every challenge shows you the
            exact PHP source code that is running. Read the code, identify the vulnerability, craft a
            payload, and retrieve the secret flag from the filesystem.
        </p>
        <div class="stats">
            <div class="stat">
                <strong><?= $total ?></strong>
                Challenges
            </div>
            <div class="stat">
                <strong><?= $completed ?></strong>
                Completed
            </div>
            <div class="stat">
                <strong>4</strong>
                Difficulty Tiers
            </div>
        </div>
        <?php if ($total > 0): ?>
        <div class="progress-bar-wrap" style="margin-top:1.25rem; max-width:400px;">
            <div class="progress-bar" style="width:<?= round(($completed / $total) * 100) ?>%"></div>
        </div>
        <p style="font-size:0.82rem; color:var(--text-muted);"><?= $completed ?> / <?= $total ?> levels completed (<?= round(($completed / $total) * 100) ?>%)</p>
        <?php endif; ?>
    </div>

    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem; flex-wrap:wrap; gap:0.5rem;">
        <p class="section-title">Challenges</p>
        <a href="submit.php" class="submit-btn" style="text-decoration:none; padding:0.4rem 0.9rem; border-radius:6px; font-size:0.85rem; font-weight:500; color:#fff; background:var(--primary);">Submit a Flag</a>
    </div>

    <div class="level-grid">
        <?php foreach ($levels as $num => $info):
            $done = is_level_completed($num);
        ?>
        <div class="level-card <?= $done ? 'completed' : '' ?>">
            <div class="level-num">Level <?= $num ?><?php if ($done): ?><span class="completed-badge">Completed</span><?php endif; ?></div>
            <span class="badge badge-<?= htmlspecialchars($info['difficulty']) ?>"><?= htmlspecialchars($info['badge']) ?></span>
            <h3><?= htmlspecialchars($info['title']) ?></h3>
            <p><?= htmlspecialchars($info['desc']) ?></p>
            <a class="level-link" href="level<?= $num ?>.php">Go to Level &rarr;</a>
        </div>
        <?php endforeach; ?>
    </div>

    <div style="margin-top:2rem; padding:1.25rem; background:var(--surface); border:1px solid var(--border); border-radius:10px; font-size:0.88rem; color:var(--text-muted);">
        <strong style="color:var(--text);">How to Play</strong>
        <ol style="margin-top:0.5rem; padding-left:1.25rem; display:flex; flex-direction:column; gap:0.4rem;">
            <li>Open a level page.</li>
            <li>Study the PHP source code on the <strong>left panel</strong> — the highlighted red line is the vulnerable point.</li>
            <li>Craft a path traversal payload in the <strong>right panel</strong> form.</li>
            <li>If the output contains a <code>FLAG{...}</code> string, the level will display your flag.</li>
            <li>Submit the flag using the <strong>Submit a Flag</strong> button to record your progress.</li>
            <li>Use progressive hints if you get stuck — each click reveals the next hint.</li>
        </ol>
    </div>

</div>
</body>
</html>
