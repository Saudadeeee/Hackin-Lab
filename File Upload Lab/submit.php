<?php
require_once __DIR__ . '/helpers.php';

$message     = '';
$messageType = '';

// Read current progress from cookie
$completed = [];
if (!empty($_COOKIE['upload_lab_progress'])) {
    $decoded = json_decode($_COOKIE['upload_lab_progress'], true);
    if (is_array($decoded)) $completed = $decoded;
}

// Handle POST submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedFlag  = trim($_POST['flag']  ?? '');
    $submittedLevel = (int)($_POST['level'] ?? 0);

    if ($submittedLevel < 1 || $submittedLevel > 10) {
        $message     = 'Please select a valid level (1–10).';
        $messageType = 'error';
    } elseif (empty($submittedFlag)) {
        $message     = 'Please enter a flag.';
        $messageType = 'error';
    } else {
        $correctFlag = get_flag_for_level($submittedLevel);
        if ($submittedFlag === $correctFlag) {
            if (!in_array($submittedLevel, $completed)) {
                $completed[] = $submittedLevel;
                sort($completed);
                setcookie('upload_lab_progress', json_encode($completed), time() + 86400 * 30, '/');
            }
            $message     = "Correct! Level {$submittedLevel} flag accepted. Well done!";
            $messageType = 'success';
        } else {
            $message     = 'Incorrect flag. Double-check your payload and try again.';
            $messageType = 'error';
        }
    }
}

// Handle clear progress
if (isset($_GET['clear'])) {
    setcookie('upload_lab_progress', '', time() - 3600, '/');
    header('Location: submit.php');
    exit;
}

$totalCompleted = count($completed);

$levelTitles = [
    1  => 'No Validation Upload',
    2  => 'Extension Blocklist Bypass',
    3  => 'Content-Type (MIME) Spoofing',
    4  => 'Magic Byte Validation Bypass',
    5  => 'Double Extension Bypass',
    6  => 'Case-Insensitive Extension Gap',
    7  => '.htaccess Handler Injection',
    8  => 'Trailing Character Bypass',
    9  => 'Content Filter (<?php) Bypass',
    10 => 'Multi-Layer WAF Bypass',
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Submit Flag — File Upload Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .header-title { font-weight: 600; color: var(--white); font-size: 1rem; letter-spacing: 0.01em; }
        .submit-page { max-width: 680px; margin: 0 auto; }
        .progress-section, .submit-form-card {
            background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg);
            padding: 1.5rem; margin-bottom: 1.5rem;
        }
        .progress-section h2, .submit-form-card h2 {
            font-size: 1rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase;
            letter-spacing: 0.07em; margin-bottom: 1rem;
        }
        .flags-list { display: flex; flex-direction: column; gap: 0.55rem; }
        .flag-row {
            display: flex; align-items: center; gap: 0.75rem; padding: 0.65rem 0.9rem; background: var(--bg);
            border: 1px solid var(--border); border-radius: var(--radius); font-size: 0.88rem;
        }
        .flag-row.found { border-color: var(--border-hi); background: var(--surface3); }
        .flag-status { width: 1.4rem; text-align: center; font-size: 1rem; flex-shrink: 0; }
        .flag-level { color: var(--text-muted); font-weight: 600; min-width: 58px; flex-shrink: 0; }
        .flag-title { color: var(--text); flex: 1; }
        .flag-value {
            font-family: 'JetBrains Mono', Consolas, monospace; font-size: 0.78rem; color: var(--white);
            background: var(--surface2); padding: 0.15rem 0.45rem; border-radius: 0; border: 1px solid var(--border);
        }
        .completion-banner {
            background: var(--surface3); border: 1px solid var(--border-hi); border-radius: var(--radius-lg);
            padding: 1.5rem; text-align: center; margin-bottom: 1.5rem;
        }
        .completion-banner h2 { color: var(--white); font-size: 1.4rem; margin-bottom: 0.5rem; }
        .completion-banner p { color: var(--text-muted); font-size: 0.9rem; }
        .progress-bar-row { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; }
        .progress-bar-outer-sm { flex: 1; background: var(--surface2); border-radius: 999px; height: 6px; overflow: hidden; }
        .progress-bar-inner-sm { height: 100%; background: var(--white); border-radius: 999px; }
    </style>
</head>
<body>

<header class="header">
    <a href="index.php" class="back-btn">&larr; Back to Levels</a>
    <div class="header-title"><span style="color:var(--primary)">&#x2B06;</span> File Upload Lab</div>
    <span></span>
</header>

<div class="container">
<div class="submit-page">

    <div class="level-header" style="justify-content:center; text-align:center; margin-bottom:1.75rem; border:none;">
        <h1 style="font-size:1.7rem; color:var(--white);">Submit a Flag</h1>
    </div>

    <?php if ($totalCompleted === 10): ?>
    <div class="completion-banner">
        <h2>&#x1F3C6; Lab Complete!</h2>
        <p>You have found all 10 flags. Excellent work — you've mastered unrestricted file-upload attack vectors.</p>
    </div>
    <?php endif; ?>

    <?php if ($message): ?>
    <div class="message <?= $messageType ?>" style="margin-bottom:1.25rem;">
        <?= htmlspecialchars($message) ?>
    </div>
    <?php endif; ?>

    <!-- Submit form -->
    <div class="submit-form-card">
        <h2>Enter Your Flag</h2>
        <form method="post" action="submit.php">
            <div class="form-group">
                <label class="form-label" for="level">Level</label>
                <select name="level" id="level" class="form-control" required>
                    <option value="">— Select Level —</option>
                    <?php for ($i = 1; $i <= 10; $i++): ?>
                    <option value="<?= $i ?>" <?= (isset($_POST['level']) && (int)$_POST['level'] === $i) ? 'selected' : '' ?>>
                        Level <?= $i ?> — <?= htmlspecialchars($levelTitles[$i]) ?>
                    </option>
                    <?php endfor; ?>
                </select>
            </div>
            <div class="form-group" style="margin-top:0.75rem;">
                <label class="form-label" for="flag">Flag</label>
                <input
                    type="text"
                    name="flag"
                    id="flag"
                    class="form-control"
                    placeholder="FLAG{...}"
                    value="<?= htmlspecialchars($_POST['flag'] ?? '') ?>"
                    autocomplete="off"
                    spellcheck="false"
                    required
                >
            </div>
            <div style="margin-top:1rem;">
                <button type="submit" class="btn btn-primary">Check Flag</button>
            </div>
        </form>
    </div>

    <!-- Progress section -->
    <div class="progress-section">
        <h2>Progress</h2>
        <div class="progress-bar-row">
            <div class="progress-bar-outer-sm">
                <div class="progress-bar-inner-sm" style="width:<?= $totalCompleted * 10 ?>%"></div>
            </div>
            <span style="font-size:0.85rem; color:var(--text-muted); white-space:nowrap;"><?= $totalCompleted ?> / 10</span>
        </div>
        <div class="flags-list">
            <?php for ($i = 1; $i <= 10; $i++):
                $found = in_array($i, $completed);
            ?>
            <div class="flag-row <?= $found ? 'found' : '' ?>">
                <span class="flag-status"><?= $found ? '&#x2705;' : '&#x25CB;' ?></span>
                <span class="flag-level">Level <?= $i ?></span>
                <span class="flag-title"><?= htmlspecialchars($levelTitles[$i]) ?></span>
                <?php if ($found): ?>
                <span class="flag-value"><?= htmlspecialchars(get_flag_for_level($i)) ?></span>
                <?php else: ?>
                <a href="level<?= $i ?>.php" style="font-size:0.8rem; color:var(--primary);">Go &rarr;</a>
                <?php endif; ?>
            </div>
            <?php endfor; ?>
        </div>

        <?php if ($totalCompleted > 0): ?>
        <div style="margin-top:1.25rem; text-align:right;">
            <a href="submit.php?clear=1"
               class="btn btn-secondary btn-sm"
               onclick="return confirm('Reset all progress?')">
                Reset Progress
            </a>
        </div>
        <?php endif; ?>
    </div>

    <div style="text-align:center; margin-top:1rem;">
        <a href="index.php" class="btn btn-secondary">&larr; Back to Level List</a>
    </div>

</div>
</div>

</body>
</html>
