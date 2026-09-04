<?php
require_once __DIR__ . '/helpers.php';

// Build level metadata
$levels = [
    1  => ['title' => 'No Validation Upload',            'difficulty' => 'Easy',   'desc' => 'The uploader saves your file verbatim into a web-served directory and runs it. Zero checks — the simplest possible upload-to-RCE.'],
    2  => ['title' => 'Extension Blocklist Bypass',      'difficulty' => 'Easy',   'desc' => 'A blocklist rejects .php but forgets .phtml, .php5, and .pht — all still executed by Apache as PHP.'],
    3  => ['title' => 'Content-Type (MIME) Spoofing',    'difficulty' => 'Medium', 'desc' => 'Validation trusts the client-supplied Content-Type header. Claim image/png while uploading a PHP shell.'],
    4  => ['title' => 'Magic Byte Validation Bypass',    'difficulty' => 'Medium', 'desc' => 'The server checks image magic bytes. A GIF89a polyglot passes the check yet still executes as PHP.'],
    5  => ['title' => 'Double Extension Bypass',         'difficulty' => 'Medium', 'desc' => 'Only the final extension is inspected. shell.php.jpg passes the image allowlist but runs as PHP.'],
    6  => ['title' => 'Case-Insensitive Extension Gap',  'difficulty' => 'Medium', 'desc' => 'A thorough blocklist compares extensions case-sensitively. Mixed-case .PhP slips straight through.'],
    7  => ['title' => '.htaccess Handler Injection',     'difficulty' => 'Hard',   'desc' => 'Scripts are blocked, but uploading an .htaccess re-maps a benign extension to the PHP handler.'],
    8  => ['title' => 'Trailing Character Bypass',       'difficulty' => 'Hard',   'desc' => 'pathinfo() is fooled by a trailing dot or space, while Apache still runs "shell.php." as code.'],
    9  => ['title' => 'Content Filter (<?php) Bypass',   'difficulty' => 'Hard',   'desc' => 'The content scanner blocks <?php. The short-echo tag <?= executes exactly the same.'],
    10 => ['title' => 'Multi-Layer WAF Bypass',          'difficulty' => 'Expert', 'desc' => 'Extension, MIME, magic-byte, and content filters stacked together. One crafted polyglot beats them all.'],
];

// Read progress from cookie
$completed = [];
if (!empty($_COOKIE['upload_lab_progress'])) {
    $decoded = json_decode($_COOKIE['upload_lab_progress'], true);
    if (is_array($decoded)) $completed = $decoded;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Upload Lab — Unrestricted File Upload Challenges</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .header-title { font-weight: 600; color: var(--white); font-size: 1rem; letter-spacing: 0.01em; }
        .submit-link {
            padding: 0.35rem 0.85rem; border-radius: 0; text-decoration: none; font-size: 0.8rem;
            font-weight: 600; color: var(--bg); background: var(--white); border: 1px solid var(--white);
        }
        .submit-link:hover { background: transparent; color: var(--white); }
        .lab-header { padding: 2.25rem 0 1.75rem; }
        .lab-header h1 { font-size: 2rem; font-weight: 700; color: var(--white); letter-spacing: -0.02em; margin-bottom: 0.5rem; }
        .lab-header h1 span { color: var(--text-muted); }
        .lab-header p { font-size: 0.9rem; color: var(--text-muted); max-width: 620px; }
        .whitebox-badge {
            display: inline-flex; align-items: center; gap: 0.4rem; background: var(--surface2);
            border: 1px solid var(--border-mid); color: var(--text-muted); padding: 0.3rem 0.8rem;
            border-radius: 999px; font-size: 0.78rem; font-weight: 600; margin-bottom: 0.85rem;
        }
        .stats-bar {
            display: flex; align-items: center; justify-content: center; gap: 2.5rem; margin: 0 auto 1.5rem;
            padding: 1rem 1.5rem; background: var(--surface); border-radius: var(--radius-lg);
            border: 1px solid var(--border); max-width: 640px; flex-wrap: wrap;
        }
        .stat { text-align: center; }
        .stat-value { font-size: 1.6rem; font-weight: 800; color: var(--white); display: block; }
        .stat-label { font-size: 0.74rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.07em; }
        .progress-bar-outer { width: 100%; max-width: 640px; margin: 0 auto 2.25rem; background: var(--surface2); border-radius: 999px; height: 8px; overflow: hidden; }
        .progress-bar-inner { height: 100%; background: var(--white); border-radius: 999px; transition: width 0.5s ease; }
        .instructions {
            max-width: 640px; margin: 0 auto 2.25rem; background: var(--surface); border: 1px solid var(--border);
            border-radius: var(--radius-lg); padding: 1.25rem 1.5rem; font-size: 0.88rem; color: var(--text-muted); line-height: 1.7;
        }
        .instructions h3 { font-size: 0.8rem; font-weight: 700; color: var(--text); text-transform: uppercase; letter-spacing: 0.07em; margin-bottom: 0.6rem; }
        .instructions ol { padding-left: 1.4rem; }
        .instructions li + li { margin-top: 0.35rem; }
        .level-card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem; gap: 0.5rem; }
        .level-number { font-size: 0.72rem; font-weight: 700; color: var(--text-faint); letter-spacing: 0.08em; text-transform: uppercase; }
        .level-card h2 { font-size: 0.9rem; font-weight: 600; color: var(--text); margin-bottom: 0.4rem; }
        .level-card.completed h2::after { content: ' \2705'; }
        .difficulty-badge { font-size: 0.62rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; padding: 2px 8px; border-radius: 0; border: 1px solid var(--border-mid); }
        .difficulty-easy   { color: #c3c0b6; border-color: #2f3546; background: #151821; }
        .difficulty-medium { color: #9a978f; border-color: #2f3546; background: #151821; }
        .difficulty-hard   { color: #9a978f; border-color: #2f3546; background: #1a1e28; }
        .difficulty-expert { color: var(--white); border-color: var(--border-hi); background: var(--surface3); }
        .start-link { display: inline-block; font-size: 0.76rem; font-weight: 600; color: var(--white); text-decoration: none; margin-top: 0.5rem; }
        .start-link:hover { color: var(--text-muted); }
        .level-card { text-decoration: none; }
    </style>
</head>
<body>

<header class="header">
    <div class="header-title"><span style="color:var(--primary)">&#x2B06;</span> File Upload Lab</div>
    <a href="submit.php" class="submit-link">Submit Flag</a>
</header>

<div class="container">
    <div class="lab-header">
        <div class="whitebox-badge">&#x1F50D; White-Box Lab</div>
        <h1>Unrestricted File Upload <span>Lab</span></h1>
        <p>Ten levels of file-upload validation bypasses that lead to remote code execution — the exact
        server-side filter is shown for every level. Read the code, defeat the filter, upload an executable
        PHP payload, and capture the flag.</p>
        <p style="margin-top:0.5rem; font-size:0.85rem;">
            <a href="submit.php" style="color:var(--primary);">Submit captured flags &rarr;</a>
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
            <li>Each level shows the <strong>actual server-side validation code</strong> running the upload.</li>
            <li>Study the filter to find the exact gap that lets an executable file through.</li>
            <li>Craft a filename, Content-Type, and file body that survive the filter, then upload it.</li>
            <li>When an executable PHP payload gets past the filter, the page awards a <code>FLAG{...}</code>. You can also click the stored file to run your shell against <code>/var/secret/</code>.</li>
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
                <span class="difficulty-badge <?= $diffClass ?>"><?= htmlspecialchars($level['difficulty']) ?></span>
            </div>
            <h2><?= htmlspecialchars($level['title']) ?></h2>
            <p><?= htmlspecialchars($level['desc']) ?></p>
            <span class="start-link"><?= $done ? 'Completed &mdash; revisit &rarr;' : 'Start Challenge &rarr;' ?></span>
        </a>
        <?php endforeach; ?>
    </div>

    <div style="text-align:center; margin-top:2rem; color:var(--text-muted); font-size:0.85rem;">
        <p>File Upload Lab &mdash; Part of the <strong>Hackin Lab</strong> web security training platform.</p>
        <p style="margin-top:0.3rem;">Run with <code>docker compose up --build</code> on port <code>8088</code>.</p>
    </div>
</div>

</body>
</html>
