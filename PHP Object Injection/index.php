<?php
require_once __DIR__ . '/helpers.php';

// Build level metadata
$levels = [
    1  => ['title' => 'Property Injection — isAdmin Bypass', 'difficulty' => 'Easy',   'desc' => 'unserialize() rebuilds an object whose properties you fully control. Flip an isAdmin flag the app trusts and walk into the admin area.'],
    2  => ['title' => '__destruct File-Read Gadget',          'difficulty' => 'Easy',   'desc' => 'A class destructor reads whatever path sits in one of its properties. Inject the object, aim the path at the secret.'],
    3  => ['title' => '__wakeup Gadget',                      'difficulty' => 'Medium', 'desc' => '__wakeup() runs automatically during unserialize(). The gadget performs its file read before you ever use the object.'],
    4  => ['title' => '__toString Gadget',                    'difficulty' => 'Medium', 'desc' => 'The app string-concatenates your object into a preview. That cast fires __toString(), which reads a file you choose.'],
    5  => ['title' => 'POP Chain (Two Gadgets)',              'difficulty' => 'Medium', 'desc' => 'Property-Oriented Programming: one gadget holds a second object and calls a method on it. Chain a destructor into a file reader.'],
    6  => ['title' => 'Type-Juggling Auth Bypass',           'difficulty' => 'Medium', 'desc' => 'The login check uses loose ==. Inject an object whose password property is a 0e "magic hash" and 0 == 0 lets you in.'],
    7  => ['title' => '__wakeup Bypass (CVE-2016-7124)',      'difficulty' => 'Hard',   'desc' => 'The gadget sanitises itself in __wakeup(). Declare a wrong property count so the engine skips __wakeup entirely.'],
    8  => ['title' => 'Phar Deserialization',                'difficulty' => 'Hard',   'desc' => 'A file operation on a phar:// path deserializes the archive metadata. Bake a gadget into the metadata and let a file_exists() fire it.'],
    9  => ['title' => 'RCE POP Chain',                       'difficulty' => 'Hard',   'desc' => 'A destructor-driven chain ends in shell_exec(). Craft the objects so the command runs cat on the secret file.'],
    10 => ['title' => 'Signed Blob WAF Bypass',              'difficulty' => 'Expert', 'desc' => 'An HMAC-signed serialized token plus a keyword WAF. Slip past the signature check and pick a gadget the blacklist never names.'],
];

// Read progress from cookie
$completed = [];
if (!empty($_COOKIE['poi_lab_progress'])) {
    $decoded = json_decode($_COOKIE['poi_lab_progress'], true);
    if (is_array($decoded)) $completed = $decoded;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP Object Injection Lab — Insecure Deserialization Challenges</title>
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
        /* level-grid card styling to match XSS index look */
        .level-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
            background: transparent;
            border: 0;
        }
        .level-card {
            display: block;
            text-decoration: none;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 1.25rem;
            transition: border-color 0.15s, transform 0.15s;
        }
        .level-card:hover { border-color: var(--border-hi); transform: translateY(-2px); }
        .level-card.completed { border-color: var(--success); }
        .level-card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.6rem; }
        .level-number { font-size: 0.72rem; font-weight: 700; color: var(--text-faint); text-transform: uppercase; letter-spacing: 0.08em; }
        .level-card h2 { font-size: 0.95rem; font-weight: 700; color: var(--text); margin-bottom: 0.4rem; }
        .level-card p { font-size: 0.8rem; color: var(--text-muted); line-height: 1.55; margin-bottom: 0.85rem; }
        .difficulty-badge { font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; padding: 2px 7px; border-radius: 3px; border: 1px solid; }
        .difficulty-easy    { color: #d0d0d0; border-color: #3a3a3a; background: #141414; }
        .difficulty-medium  { color: #b0b0b0; border-color: #3a3a3a; background: #121212; }
        .difficulty-hard    { color: #909090; border-color: #2a2a2a; background: #0e0e0e; }
        .difficulty-expert  { color: var(--white); border-color: var(--border-hi); background: var(--surface3); }
        .start-link { font-size: 0.78rem; font-weight: 600; color: #818cf8; }
        .level-card.completed .start-link { color: #34d399; }
        .lab-header { text-align: center; padding: 2.25rem 0 1.5rem; }
        .lab-header h1 { font-size: 2rem; font-weight: 800; color: var(--white); letter-spacing: -0.02em; margin-bottom: 0.5rem; }
        .lab-header h1 span { color: var(--primary); }
        .lab-header p { max-width: 620px; margin: 0 auto; color: var(--text-muted); font-size: 0.9rem; }
        .submit-link { padding: 0.35rem 0.85rem; border-radius: 5px; text-decoration: none; font-size: 0.8rem; font-weight: 600; color: var(--bg); background: var(--white); border: 1px solid var(--white); }
        .header-title { font-size: 1.05rem; font-weight: 700; color: var(--white); }
    </style>
</head>
<body>

<header class="header">
    <div class="header-title"><span>&#x1F9E9;</span> PHP Object Injection Lab</div>
    <a href="submit.php" class="submit-link">Submit Flag</a>
</header>

<div class="container">
    <div class="lab-header">
        <div class="whitebox-badge">&#x1F50D; White-Box Lab</div>
        <h1>PHP Object Injection <span>Lab</span></h1>
        <p>Ten levels of insecure deserialization. Every level calls <code>unserialize()</code> on input you control and defines the gadget classes whose magic methods do the damage. Read the code, craft an object, trigger the gadget, capture the flag.</p>
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
            <li>Each level shows the <strong>actual vulnerable PHP source</strong>, including the gadget classes and the <code>unserialize()</code> sink.</li>
            <li>Study the magic methods (<code>__wakeup</code>, <code>__destruct</code>, <code>__toString</code>) to find the dangerous action a crafted object can trigger.</li>
            <li>Build a serialized object with the <em>Payload Builder</em> on each page and submit it through the vulnerable input.</li>
            <li>When your object actually triggers the gadget effect (reaching the baked secret), the level awards a <code>FLAG{...}</code>.</li>
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
        <p>PHP Object Injection Lab &mdash; Part of the <strong>Hackin Lab</strong> web security training platform.</p>
        <p style="margin-top:0.3rem;">Run with <code>docker compose up --build</code> on port <code>8089</code>.</p>
    </div>
</div>

</body>
</html>
