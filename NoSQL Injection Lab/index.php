<?php
require_once __DIR__ . '/helpers.php';

// Build level metadata
$levels = [
    1  => ['title' => 'Auth Bypass via $ne',            'difficulty' => 'Easy',   'desc' => 'A JSON login endpoint drops your request body straight into db.users.find(). Smuggle a {"$ne":null} operator into the password field to log in as admin.'],
    2  => ['title' => 'Operator via Query String',      'difficulty' => 'Easy',   'desc' => 'PHP parses password[$ne]=x into an array. No JSON required — the operator object is born from the URL itself.'],
    3  => ['title' => '$gt Filter Bypass',              'difficulty' => 'Medium', 'desc' => 'A blacklist now blocks $ne. Reach for a different comparison operator that still matches the admin\'s unknown password.'],
    4  => ['title' => '$regex Password Extraction',     'difficulty' => 'Medium', 'desc' => 'The admin secret is never printed — only a match/no-match oracle. Recover it one character at a time with $regex anchors.'],
    5  => ['title' => '$in / $or Operator Injection',   'difficulty' => 'Medium', 'desc' => 'A document-search filter accepts your whole JSON body. Inject $in or $or to widen the results until the admin document appears.'],
    6  => ['title' => '$where JavaScript Injection',    'difficulty' => 'Medium', 'desc' => 'The filter honours MongoDB\'s $where operator, evaluating a JavaScript predicate you control. A single tautology matches everything.'],
    7  => ['title' => 'Blind Boolean Extraction',       'difficulty' => 'Hard',   'desc' => 'One bit of feedback only: login succeeds or fails. Every operator but $regex is blocked. Reconstruct the flag from the boolean oracle.'],
    8  => ['title' => 'Dollar-Keyword Filter Bypass',   'difficulty' => 'Hard',   'desc' => 'A WAF rejects any raw body containing a literal $ character. Encode the operator key with a \\u0024 unicode escape to sneak it past.'],
    9  => ['title' => 'Type-Confusion === Bypass',      'difficulty' => 'Hard',   'desc' => 'A strict if ($username === "admin") guard blocks admin logins. An array-valued username is never === a string, yet Mongo still matches.'],
    10 => ['title' => 'Multi-Layer WAF Bypass',         'difficulty' => 'Expert', 'desc' => 'Stacked defences: no literal $, string-only username, and an operator blacklist. Exactly one operator survives every layer.'],
];

// Read progress from cookie
$completed = [];
if (!empty($_COOKIE['nosql_lab_progress'])) {
    $decoded = json_decode($_COOKIE['nosql_lab_progress'], true);
    if (is_array($decoded)) $completed = $decoded;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NoSQL Injection Lab — MongoDB Query Operator Challenges</title>
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
        .stat-value { font-size: 1.6rem; font-weight: 800; color: var(--white); display: block; }
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
            background: var(--white);
            border-radius: 999px;
            transition: width 0.5s ease;
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
    <div class="header-title"><span>&#x1F4E6;</span> NoSQL Injection Lab</div>
    <a href="submit.php" class="submit-link">Submit Flag</a>
</header>

<div class="container">
    <div class="lab-header">
        <div class="whitebox-badge">&#x1F50D; White-Box Lab</div>
        <h1>NoSQL Injection <span>Challenge</span> Lab</h1>
        <p>Ten levels of MongoDB-style query-operator injection — source code provided. A JSON/array
        request builds the query object unsanitized, letting you smuggle operators like
        <code>$ne</code>, <code>$gt</code>, <code>$regex</code> and <code>$where</code> into fields the
        developer expected to be plain strings. Read the code, craft the operator, capture the flag.</p>
        <p style="margin-top:0.5rem; font-size:0.85rem;">
            <a href="submit.php" style="color:var(--white);">Submit captured flags &rarr;</a>
        </p>
    </div>

    <div class="stats-bar">
        <div class="stat">
            <span class="stat-value"><?= count($completed) ?>/10</span>
            <span class="stat-label">Completed</span>
        </div>
        <div class="stat">
            <span class="stat-value">10</span>
            <span class="stat-label">Total Levels</span>
        </div>
        <div class="stat">
            <span class="stat-value"><?= 10 - count($completed) ?></span>
            <span class="stat-label">Remaining</span>
        </div>
    </div>

    <div class="progress-bar-outer">
        <div class="progress-bar-inner" style="width: <?= count($completed) * 10 ?>%"></div>
    </div>

    <div class="instructions">
        <h3>How This Lab Works</h3>
        <ol>
            <li>Each level shows the <strong>actual vulnerable PHP source code</strong> that builds and runs the Mongo query.</li>
            <li>There is <strong>no real MongoDB</strong> — a faithful in-PHP document store evaluates operators exactly like Mongo.</li>
            <li>The admin password is a random secret you cannot guess; the only way in is to abuse a query operator.</li>
            <li>When your injection makes the query match the <code>admin</code> document, the level awards a <code>FLAG{...}</code>.</li>
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
        <p>NoSQL Injection Lab &mdash; Part of the <strong>Hackin Lab</strong> web security training platform.</p>
        <p style="margin-top:0.3rem;">Run with <code>docker compose up</code> on port <code>8090</code>.</p>
    </div>
</div>

</body>
</html>
