<?php
require_once __DIR__ . '/helpers.php';

// Build level metadata
$levels = [
    1  => ['title' => 'Basic Open Redirect',            'difficulty' => 'Easy',   'desc' => 'The next parameter is handed straight to header("Location: ...") with zero validation. The simplest possible open redirect.'],
    2  => ['title' => 'Protocol-Relative Redirect',     'difficulty' => 'Easy',   'desc' => 'The filter only allows values that start with "/", assuming a leading slash means a same-site path. A // prefix sails through.'],
    3  => ['title' => 'Prefix Allowlist Bypass',        'difficulty' => 'Medium', 'desc' => 'The host is checked with str_starts_with($host, "example-bank.local"). A crafted subdomain of the attacker domain matches the prefix.'],
    4  => ['title' => 'Substring Allowlist Bypass',     'difficulty' => 'Medium', 'desc' => 'The filter requires the trusted name to appear somewhere in the URL. Drop it in the path and the real host is still yours.'],
    5  => ['title' => 'Backslash Normalization',        'difficulty' => 'Medium', 'desc' => 'Protocol-relative and absolute URLs are blocked, but browsers turn backslashes into slashes — turning /\\ into //.'],
    6  => ['title' => 'Userinfo (@) Host Spoof',        'difficulty' => 'Medium', 'desc' => 'A naive regex extracts the authority and prefix-checks it. Userinfo before an @ fools the check while the browser connects elsewhere.'],
    7  => ['title' => 'Encoded Slash Bypass',           'difficulty' => 'Hard',   'desc' => 'The value is checked raw, then urldecode()d before redirecting. %2f%2f passes the check and decodes to //.'],
    8  => ['title' => 'Dangerous Scheme Redirect',      'difficulty' => 'Hard',   'desc' => 'The allowlist only inspects the host. Schemes like javascript: and data: have no host, so they slip past and execute.'],
    9  => ['title' => 'CRLF Header Injection',          'difficulty' => 'Hard',   'desc' => 'The decoded value is concatenated into the Location header. A CRLF sequence injects arbitrary response headers.'],
    10 => ['title' => 'Multi-Layer Filter Bypass',      'difficulty' => 'Expert', 'desc' => 'Five stacked layers block every earlier trick. One gap survives: a single-slash scheme that parse_url() reads as hostless.'],
];

// Read progress from cookie
$completed = [];
if (!empty($_COOKIE['redirect_lab_progress'])) {
    $decoded = json_decode($_COOKIE['redirect_lab_progress'], true);
    if (is_array($decoded)) $completed = $decoded;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Open Redirect Lab — Unvalidated Redirect Challenges</title>
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
    <div class="header-title"><span>&#x21AA;</span> Open Redirect Lab</div>
    <a href="submit.php" class="submit-link">Submit Flag</a>
</header>

<div class="container">
    <div class="lab-header">
        <div class="whitebox-badge">&#x1F50D; White-Box Lab</div>
        <h1>Open Redirect <span>Challenge</span> Lab</h1>
        <p>Ten levels of unvalidated-redirect vulnerabilities — source code provided. Each level takes a <code>next</code> parameter and redirects with a progressively stronger (but flawed) allowlist. Steer the redirect to the attacker host to capture the flag.</p>
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
            <li>The trusted host is <code>example-bank.local</code>; the attacker host is <code>evil.attacker.example</code>.</li>
            <li>Craft a <code>next</code> value that survives the level's filter yet resolves to the attacker host.</li>
            <li>The lab <strong>computes</strong> the destination the browser would load — it never issues the live redirect.</li>
            <li>If the effective destination lands off the allowlist, you receive a <code>FLAG{...}</code> string.</li>
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
        <p>Open Redirect Lab &mdash; Part of the <strong>Hackin Lab</strong> web security training platform.</p>
        <p style="margin-top:0.3rem;">Run with <code>docker compose up</code> on port <code>8092</code>.</p>
    </div>
</div>

</body>
</html>
