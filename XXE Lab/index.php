<?php
require_once __DIR__ . '/helpers.php';

$levels = get_level_meta();

// Read progress from cookie
$completed = [];
if (!empty($_COOKIE['xxe_lab_progress'])) {
    $decoded = json_decode($_COOKIE['xxe_lab_progress'], true);
    if (is_array($decoded)) $completed = $decoded;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XXE Lab — XML External Entity Challenges</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .stats-bar {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 2rem;
            margin: 0 auto 2rem;
            padding: 1rem 1.5rem;
            background: var(--surface);
            border-radius: var(--radius-lg);
            border: 1px solid var(--border);
            max-width: 640px;
            flex-wrap: wrap;
        }
        .stat { text-align: center; }
        .stat-value { font-size: 1.6rem; font-weight: 800; color: var(--primary); display: block; }
        .stat-label { font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.07em; }
        .progress-bar-outer {
            width: 100%;
            max-width: 640px;
            margin: 0 auto 2.5rem;
            background: var(--surface2);
            border-radius: 999px;
            height: 8px;
            overflow: hidden;
        }
        .progress-bar-inner {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), #6f9fb0);
            border-radius: 999px;
            transition: width 0.5s ease;
        }
        .whitebox-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            background: rgba(111, 159, 176,0.12);
            border: 1px solid var(--primary);
            color: #6f9fb0;
            padding: 0.35rem 0.85rem;
            border-radius: 999px;
            font-size: 0.82rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
        }
        .instructions {
            max-width: 640px;
            margin: 0 auto 2rem;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 1.25rem 1.5rem;
            font-size: 0.9rem;
            color: var(--text-muted);
            line-height: 1.7;
        }
        .instructions h3 {
            font-size: 0.85rem;
            font-weight: 700;
            color: var(--text);
            text-transform: uppercase;
            letter-spacing: 0.07em;
            margin-bottom: 0.6rem;
        }
        .instructions ol { padding-left: 1.4rem; }
        .instructions li + li { margin-top: 0.35rem; }
        .lab-header { text-align: center; padding: 2.5rem 0 1.75rem; }
        .lab-header h1 { font-size: 2rem; font-weight: 700; color: var(--white); letter-spacing: -0.02em; }
        .lab-header h1 span { color: var(--primary); }
        .lab-header p { font-size: 0.9rem; color: var(--text-muted); max-width: 560px; margin: 0.6rem auto 0; }
        .level-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1px;
            background: var(--border);
            border: 1px solid var(--border);
            border-radius: 0;
            overflow: hidden;
            margin-bottom: 2rem;
        }
        .level-card {
            background: var(--surface);
            padding: 1.25rem;
            transition: background 0.15s;
            text-decoration: none;
            display: block;
        }
        .level-card:hover { background: var(--surface2); }
        .level-card.completed { background: rgba(127, 160, 109,0.05); }
        .level-card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.6rem; }
        .level-number { font-size: 0.72rem; font-weight: 700; color: var(--text-faint); text-transform: uppercase; letter-spacing: 0.08em; }
        .level-card h2 { font-size: 0.95rem; font-weight: 600; color: var(--text); margin-bottom: 0.4rem; }
        .level-card p { font-size: 0.8rem; color: var(--text-muted); line-height: 1.55; margin-bottom: 0.75rem; }
        .start-link { font-size: 0.78rem; font-weight: 600; color: var(--primary-hover); }
        .difficulty-badge {
            display: inline-block; font-size: 0.65rem; font-weight: 700; text-transform: uppercase;
            letter-spacing: 0.06em; padding: 2px 7px; border-radius: 0; border: 1px solid;
        }
        .difficulty-easy   { color: #c3c0b6; border-color: #2f3546; background: #151821; }
        .difficulty-medium { color: #9a978f; border-color: #2f3546; background: #151821; }
        .difficulty-hard   { color: #9a978f; border-color: #2f3546; background: #1a1e28; }
        .difficulty-expert { color: var(--white); border-color: var(--border-hi); background: var(--surface3); }
    </style>
</head>
<body>

<header class="header">
    <div class="header-title"><span>&#x1F5CE;</span> XXE Lab</div>
    <a href="submit.php" class="submit-link">Submit Flag</a>
</header>

<div class="container">
    <div class="lab-header">
        <div class="whitebox-badge">&#x1F50D; White-Box Lab</div>
        <h1>XXE <span>Challenge</span> Lab</h1>
        <p>Ten levels of XML External Entity vulnerabilities — source code provided. Read the code, craft a malicious DOCTYPE, and make the parser exfiltrate the secret.</p>
        <p style="margin-top:0.4rem; font-size:0.85rem;">
            <a href="submit.php" style="color:#6f9fb0;">Submit captured flags &rarr;</a>
        </p>
    </div>

    <div class="stats-bar">
        <div class="stat">
            <span class="stat-value"><?= count($completed) ?>/10</span>
            <span class="stat-label">Completed</span>
        </div>
        <div class="stat">
            <span class="stat-value" style="color:#7fa06d;">10</span>
            <span class="stat-label">Total Levels</span>
        </div>
        <div class="stat">
            <span class="stat-value" style="color:#cfa65c;"><?= 10 - count($completed) ?></span>
            <span class="stat-label">Remaining</span>
        </div>
    </div>

    <div class="progress-bar-outer">
        <div class="progress-bar-inner" style="width: <?= count($completed) * 10 ?>%"></div>
    </div>

    <div class="instructions">
        <h3>How This Lab Works</h3>
        <ol>
            <li>Each level shows the <strong>actual vulnerable PHP source code</strong> running the challenge.</li>
            <li>The parser is configured to <em>enable</em> external entities on purpose (modern libxml disables them).</li>
            <li>Craft an XML payload whose entity resolves the secret at <code>/var/secret/flagN.txt</code>.</li>
            <li>When the resolved output really contains the flag, the page reveals your <code>FLAG{...}</code>.</li>
            <li>Copy the flag to the <a href="submit.php">Submit Flag</a> page to mark the level complete.</li>
        </ol>
    </div>

    <div class="level-grid">
        <?php foreach ($levels as $id => $level):
            $done = in_array($id, $completed);
            $diffClass = 'difficulty-' . strtolower($level['difficulty']);
        ?>
        <a href="level<?= $id ?>.php" class="level-card <?= $done ? 'completed' : '' ?>">
            <div class="level-card-header">
                <span class="level-number">Level <?= $id ?></span>
                <span class="difficulty-badge <?= $diffClass ?>"><?= htmlspecialchars($level['badge']) ?></span>
            </div>
            <h2><?= htmlspecialchars($level['title']) ?></h2>
            <p><?= htmlspecialchars($level['desc']) ?></p>
            <div class="start-link">
                <?= $done ? '&#x2705; Completed' : 'Start Challenge &rarr;' ?>
            </div>
        </a>
        <?php endforeach; ?>
    </div>

    <div style="text-align:center; margin-top:2rem; color:var(--text-muted); font-size:0.85rem;">
        <p>XXE Lab &mdash; Part of the <strong>Hackin Lab</strong> web security training platform.</p>
        <p style="margin-top:0.3rem;">Run with <code>docker compose up --build</code> on port <code>8087</code>.</p>
    </div>
</div>

</body>
</html>
