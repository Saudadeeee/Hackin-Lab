<?php
require_once __DIR__ . '/helpers.php';

// Build level metadata
$levels = [
    1  => ['title' => 'Basic SSRF',                     'difficulty' => 'Easy',   'desc' => 'The server fetches any URL you supply with zero validation. Point it at a loopback-only internal page to read a secret your browser can never reach.'],
    2  => ['title' => 'Internal Service Access',        'difficulty' => 'Easy',   'desc' => 'A private admin panel is bound to 127.0.0.1 and returns 403 to outsiders. Use the fetcher as a proxy to reach the internal management interface.'],
    3  => ['title' => 'Blind SSRF',                     'difficulty' => 'Medium', 'desc' => 'The response body is hidden from you. The request still fires internally — the server confirms the internal beacon was hit entirely on its side.'],
    4  => ['title' => 'Host Blocklist Bypass',          'difficulty' => 'Medium', 'desc' => 'A naive blocklist rejects the strings localhost and 127.0.0.1. Alternate IP encodings — 127.1, 0, decimal, [::1] — all reach loopback anyway.'],
    5  => ['title' => 'Redirect-Based SSRF',            'difficulty' => 'Medium', 'desc' => 'The allowlist checks only the host you submit, but the fetcher follows 302 redirects. Bounce off an open redirector on the trusted host into the internal network.'],
    6  => ['title' => 'Scheme Abuse: file://',          'difficulty' => 'Medium', 'desc' => 'The fetcher never validates the URL scheme. Swap http:// for file:// and read a secret straight off the server\'s disk, outside the web root.'],
    7  => ['title' => 'URL Parser Confusion',           'difficulty' => 'Hard',   'desc' => 'The allowlist substring-matches example.com in the authority. Userinfo before an @ satisfies the check while the real connection lands on 127.0.0.1.'],
    8  => ['title' => 'Cloud Metadata Theft',           'difficulty' => 'Hard',   'desc' => 'A mock instance-metadata service lives at 169.254.169.254, reachable only from inside the box. Query the IAM credentials path to leak the instance secret.'],
    9  => ['title' => 'Hostname Allowlist Bypass',      'difficulty' => 'Hard',   'desc' => 'Trust is decided by a hostname substring. An attacker-controlled name that contains the magic substring and resolves to loopback sails through.'],
    10 => ['title' => 'Multi-Layer WAF Bypass',         'difficulty' => 'Expert', 'desc' => 'Scheme, host-literal, and keyword filters stack together and block every earlier trick. One uncovered vector — decimal-encoded loopback — slips past all three.'],
];

// Read progress from cookie
$completed = [];
if (!empty($_COOKIE['ssrf_lab_progress'])) {
    $decoded = json_decode($_COOKIE['ssrf_lab_progress'], true);
    if (is_array($decoded)) $completed = $decoded;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSRF Lab — Server-Side Request Forgery Challenges</title>
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
    <div class="header-title"><span>&#x1F310;</span> SSRF Lab</div>
    <a href="submit.php" class="submit-link">Submit Flag</a>
</header>

<div class="container">
    <div class="lab-header">
        <div class="whitebox-badge">&#x1F50D; White-Box Lab</div>
        <h1>SSRF <span>Challenge</span> Lab</h1>
        <p>Ten levels of Server-Side Request Forgery — source code provided. Read the code, find the flaw, craft a URL that makes the server fetch what you cannot, and capture the flag.</p>
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
            <li>Each level shows the <strong>actual vulnerable PHP source code</strong> running the challenge.</li>
            <li>Study the code to see <em>exactly</em> how it fetches your URL and where the guardrail fails.</li>
            <li>Craft a URL that makes the <strong>server</strong> request an internal resource on your behalf.</li>
            <li>When the fetched response actually contains the internal <code>FLAG{...}</code>, the level awards it.</li>
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
        <p>SSRF Lab &mdash; Part of the <strong>Hackin Lab</strong> web security training platform.</p>
        <p style="margin-top:0.3rem;">Run with <code>docker compose up --build</code> on port <code>8085</code>.</p>
    </div>
</div>

</body>
</html>
