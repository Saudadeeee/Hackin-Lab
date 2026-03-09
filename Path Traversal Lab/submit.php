<?php
require_once __DIR__ . '/helpers.php';

$levels   = get_level_info();
$message  = '';
$msgClass = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submitted = trim($_POST['flag'] ?? '');
    $found     = false;
    foreach ($levels as $num => $info) {
        $expected = get_flag_for_level($num);
        if ($submitted === $expected) {
            mark_level_completed($num);
            $message  = "Correct! Flag for Level {$num} ({$info['title']}) accepted. Well done!";
            $msgClass = 'success';
            $found    = true;
            break;
        }
    }
    if (!$found && !empty($submitted)) {
        $message  = 'Incorrect flag. Double-check your payload output and copy the exact FLAG{...} string.';
        $msgClass = 'error';
    }
}

$progress  = get_progress();
$completed = count($progress);
$total     = count($levels);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Submit Flag - Path Traversal Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
<div class="header">
    <div>
        <h1>Path Traversal Lab</h1>
        <p>Submit your flag</p>
    </div>
    <a href="index.php" class="back-btn">Back to Levels</a>
</div>
<div class="container">
    <div class="submit-page">
        <h2>Submit a Flag</h2>
        <p>
            Paste the <code>FLAG{...}</code> string you found in the challenge output.
            Your progress is stored in a browser cookie.
        </p>

        <?php if (!empty($message)): ?>
        <div class="message <?= $msgClass ?>"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>

        <form method="POST" action="submit.php">
            <div class="form-group">
                <label for="flag">Flag</label>
                <input type="text" id="flag" name="flag" class="flag-input"
                       placeholder="FLAG{...}" autocomplete="off"
                       value="<?= htmlspecialchars($_POST['flag'] ?? '') ?>">
            </div>
            <button type="submit" class="btn btn-primary" style="margin-top:0.5rem;">Submit Flag</button>
        </form>

        <div style="margin-top:2rem;">
            <p style="font-size:0.88rem; color:var(--text-muted); margin-bottom:0.75rem;">
                Progress: <strong style="color:var(--text);"><?= $completed ?> / <?= $total ?></strong> levels completed
            </p>
            <div class="progress-bar-wrap">
                <div class="progress-bar" style="width:<?= $total > 0 ? round(($completed/$total)*100) : 0 ?>%"></div>
            </div>
            <ul class="progress-list" style="margin-top:1rem;">
                <?php foreach ($levels as $num => $info):
                    $done = is_level_completed($num);
                ?>
                <li class="<?= $done ? 'done' : '' ?>">
                    <span class="check"><?= $done ? '&#10003;' : $num ?></span>
                    Level <?= $num ?> &mdash; <?= htmlspecialchars($info['title']) ?>
                    <?php if ($done): ?><span class="completed-badge">Done</span><?php endif; ?>
                </li>
                <?php endforeach; ?>
            </ul>
        </div>

        <div style="margin-top:2rem;">
            <a href="index.php" class="nav-link" style="text-decoration:none;">Back to All Levels</a>
        </div>
    </div>
</div>
</body>
</html>
