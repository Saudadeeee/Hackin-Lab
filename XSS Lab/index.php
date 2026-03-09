<?php
require_once __DIR__ . '/helpers.php';

// Build level metadata
$levels = [
    1  => ['title' => 'Basic Reflected XSS',                'difficulty' => 'Easy',   'desc' => 'A GET parameter is concatenated directly into the HTML output with zero sanitization. The simplest possible XSS entry point.'],
    2  => ['title' => 'XSS in HTML Attribute',              'difficulty' => 'Easy',   'desc' => 'htmlspecialchars() is called with ENT_NOQUOTES, leaving double-quote characters unescaped inside an HTML attribute context.'],
    3  => ['title' => 'Stored XSS via Comments',            'difficulty' => 'Medium', 'desc' => 'User-supplied comments are saved to a file and rendered back to every visitor without HTML encoding — classic stored XSS.'],
    4  => ['title' => 'DOM-based XSS via innerHTML',        'difficulty' => 'Medium', 'desc' => 'A URL parameter is read by client-side JavaScript and assigned to innerHTML. The server never touches the payload.'],
    5  => ['title' => 'htmlspecialchars Without ENT_QUOTES','difficulty' => 'Medium', 'desc' => 'Default htmlspecialchars() (ENT_COMPAT) does not escape single quotes. The value lives inside a single-quoted attribute.'],
    6  => ['title' => 'Bypass Script Tag Filter',           'difficulty' => 'Medium', 'desc' => 'A naive str_replace removes lowercase &lt;script&gt; only. Uppercase variants and alternative vectors sail straight through.'],
    7  => ['title' => 'XSS via href Attribute',             'difficulty' => 'Hard',   'desc' => 'A URL parameter is placed directly in an href attribute with no scheme validation, enabling javascript: URI execution.'],
    8  => ['title' => 'XSS via JSON API Response',          'difficulty' => 'Hard',   'desc' => 'An API endpoint embeds your input in JSON. The client fetches the JSON and assigns data.message straight to innerHTML.'],
    9  => ['title' => 'Bypass XSS Blacklist',               'difficulty' => 'Hard',   'desc' => 'A short blacklist blocks &lt;script&gt;, javascript:, onload= and onclick= — but dozens of other event handlers are unguarded.'],
    10 => ['title' => 'Multi-Layer XSS Filter Bypass',      'difficulty' => 'Expert', 'desc' => 'Three filter layers strip script tags, six event handlers, and HTML comments. Find a vector that none of the layers cover.'],
];

// Read progress from cookie
$completed = [];
if (!empty($_COOKIE['xss_lab_progress'])) {
    $decoded = json_decode($_COOKIE['xss_lab_progress'], true);
    if (is_array($decoded)) $completed = $decoded;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Lab — Cross-Site Scripting Challenges</title>
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
            background: linear-gradient(90deg, var(--primary), #818cf8);
            border-radius: 999px;
            transition: width 0.5s ease;
        }
        .whitebox-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            background: rgba(79,70,229,0.12);
            border: 1px solid var(--primary);
            color: #a5b4fc;
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
    </style>
</head>
<body>

<header class="header">
    <div class="header-title"><span>&#x26A1;</span> XSS Lab</div>
    <a href="submit.php" class="submit-link">Submit Flag</a>
</header>

<div class="container">
    <div class="lab-header">
        <div class="whitebox-badge">&#x1F50D; White-Box Lab</div>
        <h1>XSS <span>Challenge</span> Lab</h1>
        <p>Ten levels of Cross-Site Scripting vulnerabilities — source code provided. Read the code, find the flaw, craft your payload, capture the flag.</p>
        <p style="margin-top:0.4rem; font-size:0.85rem;">
            <a href="submit.php" style="color:#818cf8;">Submit captured flags &rarr;</a>
        </p>
    </div>

    <div class="stats-bar">
        <div class="stat">
            <span class="stat-value"><?= count($completed) ?>/10</span>
            <span class="stat-label">Completed</span>
        </div>
        <div class="stat">
            <span class="stat-value" style="color:#34d399;">10</span>
            <span class="stat-label">Total Levels</span>
        </div>
        <div class="stat">
            <span class="stat-value" style="color:#fbbf24;"><?= 10 - count($completed) ?></span>
            <span class="stat-label">Remaining</span>
        </div>
    </div>

    <div class="progress-bar-outer">
        <div class="progress-bar-inner" style="width: <?= count($completed) * 10 ?>%"></div>
    </div>

    <div class="instructions">
        <h3>How This Lab Works</h3>
        <ol>
            <li>Each level shows the <strong>actual vulnerable PHP/JS source code</strong> running the challenge.</li>
            <li>Study the code to identify <em>exactly</em> where and how the vulnerability exists.</li>
            <li>Craft a payload that exploits the vulnerability and submit it in the input form.</li>
            <li>If the server-side verifier accepts your payload, you receive a <code>FLAG{...}</code> string.</li>
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
                <span class="difficulty-badge <?= $diffClass ?>"><?= $level['difficulty'] ?></span>
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
        <p>XSS Lab &mdash; Part of the <strong>Hackin Lab</strong> web security training platform.</p>
        <p style="margin-top:0.3rem;">Run with <code>docker-compose up</code> on port <code>8081</code>.</p>
    </div>
</div>

</body>
</html>
