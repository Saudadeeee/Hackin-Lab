<?php
require_once __DIR__ . '/helpers.php';

// Build level metadata
$levels = [
    1  => ['title' => 'No-Token GET State Change',   'difficulty' => 'Easy',   'desc' => 'A sensitive account change is exposed over GET with no anti-CSRF token. A single &lt;img&gt; tag forces it as the logged-in admin.'],
    2  => ['title' => 'No-Token POST Form',          'difficulty' => 'Easy',   'desc' => 'Requiring POST is not a defense. An auto-submitting cross-site form sends the admin cookie and changes state — still no token.'],
    3  => ['title' => 'Unvalidated CSRF Token',      'difficulty' => 'Medium', 'desc' => 'The form carries a csrf_token field, but the server-side comparison was left commented out. The token is never actually checked.'],
    4  => ['title' => 'Static / Predictable Token',  'difficulty' => 'Medium', 'desc' => 'The expected token is a hardcoded constant, identical for every session. The attacker simply reads it and replays it.'],
    5  => ['title' => 'Token Not Bound to Session',  'difficulty' => 'Medium', 'desc' => 'The handler checks the token format (32 hex chars) but never compares it to the session token. Any well-formed value passes.'],
    6  => ['title' => 'SameSite=Lax Bypass',         'difficulty' => 'Medium', 'desc' => 'The cookie is SameSite=Lax with no token. A top-level GET navigation still carries the cookie and triggers the change.'],
    7  => ['title' => 'JSON Endpoint via text/plain','difficulty' => 'Hard',   'desc' => 'A JSON API assumed safe by CORS preflight. A simple text/plain body that is valid JSON reaches it with no preflight.'],
    8  => ['title' => 'Referer Check Bypass',        'difficulty' => 'Hard',   'desc' => 'A naive Referer check blocks a present cross-site Referer but fails open when the header is suppressed with a no-referrer policy.'],
    9  => ['title' => 'Double-Submit Cookie Flaw',   'difficulty' => 'Hard',   'desc' => 'Double-submit only checks cookie == body. The non-HttpOnly token cookie lets the attacker set both sides to the same value.'],
    10 => ['title' => 'Multi-Layer Defense Bypass',  'difficulty' => 'Expert', 'desc' => 'Token + SameSite=Lax + Referer stacked together, each with the gap you already met. One crafted GET navigation defeats all three.'],
];

// Read progress from cookie
$completed = [];
if (!empty($_COOKIE['csrf_lab_progress'])) {
    $decoded = json_decode($_COOKIE['csrf_lab_progress'], true);
    if (is_array($decoded)) $completed = $decoded;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSRF Lab — Cross-Site Request Forgery Challenges</title>
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
        .lab-header { padding: 2rem 0 1.5rem; }
        .lab-header h1 { font-size: 2rem; font-weight: 800; color: var(--white); letter-spacing: -0.02em; margin-bottom: 0.5rem; }
        .lab-header h1 span { color: var(--primary); }
        .lab-header > p { font-size: 0.92rem; color: var(--text-muted); max-width: 640px; line-height: 1.7; }
        .level-card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.6rem; }
        .level-number { font-size: 0.72rem; font-weight: 700; color: var(--text-faint); letter-spacing: 0.08em; text-transform: uppercase; }
        .difficulty-badge { font-size: 0.62rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; padding: 2px 7px; border-radius: 3px; border: 1px solid var(--border-mid); color: var(--text-muted); }
        .difficulty-expert { color: var(--white); border-color: var(--border-hi); background: var(--surface3); }
        .level-card { text-decoration: none; display: block; }
        .level-card h2 { font-size: 0.9rem; font-weight: 600; color: var(--text); margin-bottom: 0.4rem; }
        .start-link { font-size: 0.76rem; font-weight: 600; color: var(--primary); margin-top: 0.75rem; }
        .level-card.completed { border-left: 2px solid var(--white); }
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
    <div class="header-title"><span style="color:var(--primary)">&#x1F6E1;</span> CSRF Lab</div>
    <a href="submit.php" class="submit-btn">Submit Flag</a>
</header>

<div class="container">
    <div class="lab-header">
        <div class="whitebox-badge">&#x1F50D; White-Box Lab</div>
        <h1>CSRF <span>Challenge</span> Lab</h1>
        <p>Ten levels of Cross-Site Request Forgery. Each level protects an admin action (change the account email, promote a user) with a different (broken) defense. Read the handler, craft a PoC, and deliver it to the simulated logged-in admin — the bot performs your request with the admin session attached, exactly like a real victim.</p>
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
            <li>Each level shows the <strong>actual vulnerable PHP handler</strong> for a state-changing admin action.</li>
            <li>Study the (missing or flawed) anti-CSRF check to see how the request can be forged.</li>
            <li>Write a PoC — a URL, an <code>&lt;img&gt;</code>/<code>&lt;form&gt;</code>, or a <code>fetch()</code> — in the editor.</li>
            <li>Click <strong>Deliver to victim</strong>: <code>visit.php</code> runs your request <em>as the admin</em>. If it changes state without a valid token, you get a <code>FLAG{...}</code>.</li>
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
            <p><?= $level['desc'] ?></p>
            <div class="start-link">
                <?= $done ? '&#x2705; Completed' : 'Start Challenge &rarr;' ?>
            </div>
        </a>
        <?php endforeach; ?>
    </div>

    <div style="text-align:center; margin-top:2rem; color:var(--text-muted); font-size:0.85rem;">
        <p>CSRF Lab &mdash; Part of the <strong>Hackin Lab</strong> web security training platform.</p>
        <p style="margin-top:0.3rem;">Run with <code>docker compose up</code> on port <code>8091</code>.</p>
    </div>
</div>

</body>
</html>
