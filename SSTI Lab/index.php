<?php
require_once __DIR__ . '/helpers.php';

// Build level metadata
$levels = [
    1  => ['title' => 'Basic Template Injection',        'difficulty' => 'Easy',   'desc' => 'A hand-rolled template engine evaluates {{ ... }} expressions as raw PHP via eval(). The simplest SSTI entry point — {{7*7}} becomes 49.'],
    2  => ['title' => 'Variable & Superglobal Access',    'difficulty' => 'Easy',   'desc' => 'The expression runs in global scope, so every superglobal is reachable. Read $_SERVER, $_ENV and $GLOBALS straight out of the template.'],
    3  => ['title' => 'Function Call Execution',          'difficulty' => 'Medium', 'desc' => 'Raw PHP means arbitrary function calls. Fingerprint the interpreter and manipulate strings with phpversion(), strrev(), php_uname() and friends.'],
    4  => ['title' => 'Local File Disclosure',            'difficulty' => 'Medium', 'desc' => 'If functions run, file readers run. Point file_get_contents() at the baked secret /var/secret/flag.txt and disclose it through the template.'],
    5  => ['title' => 'Remote Code Execution',            'difficulty' => 'Medium', 'desc' => 'Escalate from file reads to full command execution with system(), shell_exec() or backticks. Prove it by running id.'],
    6  => ['title' => 'Keyword Blocklist Bypass',         'difficulty' => 'Medium', 'desc' => 'A filter rejects system/exec/shell_exec/passthru by name. Reach RCE with backticks or a split-string call_user_func the substring filter never sees.'],
    7  => ['title' => 'Character Blocklist Bypass',       'difficulty' => 'Hard',   'desc' => 'Quotes and backticks are banned. Build command strings with chr() concatenation or chain a numeric-key $_GET parameter — no quotes required.'],
    8  => ['title' => 'Variable-Function Indirection',    'difficulty' => 'Hard',   'desc' => 'Command names and call_user_func are all blocked. Assemble the function name in a variable and invoke it: $f=\'sys\'.\'tem\';$f(\'id\').'],
    9  => ['title' => 'Nested Delimiter Bypass',          'difficulty' => 'Hard',   'desc' => 'A naive sanitizer strips one {{ ... }} layer before rendering — but only once. Nest the braces so a valid tag survives the single pass.'],
    10 => ['title' => 'Multi-Layer WAF Bypass',           'difficulty' => 'Expert', 'desc' => 'Keyword blocklist, character blocklist and the non-recursive delimiter stripper, all stacked. Craft the one vector that survives every layer.'],
];

// Read progress from cookie
$completed = [];
if (!empty($_COOKIE['ssti_lab_progress'])) {
    $decoded = json_decode($_COOKIE['ssti_lab_progress'], true);
    if (is_array($decoded)) $completed = $decoded;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSTI Lab — Server-Side Template Injection Challenges</title>
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
    <div class="header-title"><span>&#x26A1;</span> SSTI Lab</div>
    <a href="submit.php" class="submit-link">Submit Flag</a>
</header>

<div class="container">
    <div class="lab-header">
        <div class="whitebox-badge">&#x1F50D; White-Box Lab</div>
        <h1>SSTI <span>Challenge</span> Lab</h1>
        <p>Ten levels of Server-Side Template Injection against a deliberately-vulnerable mini template engine — source code provided. Read the code, find the flaw, craft your payload, capture the flag.</p>
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
            <li>Study the code to identify <em>exactly</em> where and how the template engine evaluates your input.</li>
            <li>Craft a <code>{{ ... }}</code> payload that exploits the engine and submit it in the input form.</li>
            <li>The page renders your input for real and the server-side verifier confirms code execution — then awards a <code>FLAG{...}</code>.</li>
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
        <p>SSTI Lab &mdash; Part of the <strong>Hackin Lab</strong> web security training platform.</p>
        <p style="margin-top:0.3rem;">Run with <code>docker compose up --build</code> on port <code>8086</code>.</p>
    </div>
</div>

</body>
</html>
