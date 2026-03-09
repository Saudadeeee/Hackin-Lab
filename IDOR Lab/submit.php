<?php
require_once __DIR__ . '/helpers.php';

$flags = [];
for ($i = 1; $i <= 10; $i++) {
    $flags[$i] = get_flag_for_level($i);
}

// Load progress from cookie
$progress = [];
$rawCookie = $_COOKIE['idor_lab_progress'] ?? '';
if ($rawCookie) {
    $decoded = json_decode(base64_decode($rawCookie), true);
    if (is_array($decoded)) $progress = $decoded;
}

$message = '';
$messageType = '';
$submittedFlag = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedFlag = trim($_POST['flag'] ?? '');
    $found = false;
    foreach ($flags as $levelId => $correctFlag) {
        if (strcasecmp($submittedFlag, $correctFlag) === 0) {
            $found = true;
            if (!in_array($levelId, $progress)) {
                $progress[] = $levelId;
                sort($progress);
            }
            $message     = "Correct! Flag for Level $levelId accepted.";
            $messageType = 'success';
            break;
        }
    }
    if (!$found) {
        $message     = 'Incorrect flag. Keep trying!';
        $messageType = 'error';
    }
    // Save progress
    $encoded = base64_encode(json_encode($progress));
    setcookie('idor_lab_progress', $encoded, time() + 86400 * 30, '/');
}

$levelNames = [
    1  => 'Basic IDOR',
    2  => 'IDOR File Download',
    3  => 'Hidden Form Field Tampering',
    4  => 'Horizontal Privilege Escalation',
    5  => 'Mass Assignment',
    6  => 'Cookie Role Forgery',
    7  => 'API IDOR',
    8  => 'Predictable Reset Token',
    9  => 'JWT No Signature Verification',
    10 => 'Race Condition (TOCTOU)',
];

html_open('Submit Flag — IDOR Lab');
?>
<div class="header">
    <div>
        <h1>Flag Submission</h1>
        <p>Submit captured flags to track your progress</p>
    </div>
    <a href="index.php" class="back-btn">&#8592; Lab Home</a>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;">

    <div>
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.25rem;margin-bottom:1.5rem;">
            <h3 style="margin-bottom:0.75rem;font-size:1rem;padding-bottom:0.5rem;border-bottom:1px solid var(--border);">Submit a Flag</h3>
            <?php if ($message): ?>
            <div class="message <?= $messageType ?>">
                <?= htmlspecialchars($message) ?>
            </div>
            <?php endif; ?>
            <form method="POST" action="submit.php">
                <div class="form-group">
                    <label for="flag">Flag</label>
                    <input type="text" id="flag" name="flag" class="form-control"
                           placeholder="FLAG{...}"
                           value="<?= htmlspecialchars($submittedFlag) ?>"
                           autocomplete="off">
                </div>
                <button type="submit" class="btn btn-primary">Submit Flag</button>
            </form>
        </div>

        <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.25rem;">
            <h3 style="margin-bottom:0.75rem;font-size:1rem;padding-bottom:0.5rem;border-bottom:1px solid var(--border);">Flag Format</h3>
            <p style="color:var(--text-muted);font-size:0.88rem;margin-bottom:0.5rem;">All flags follow the format:</p>
            <div class="flag-display">FLAG{descriptive_name_here}</div>
            <p style="color:var(--text-muted);font-size:0.85rem;">Flags are found within page content, database records, API responses, or cookies when you successfully exploit the vulnerability.</p>
        </div>
    </div>

    <div>
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.25rem;">
            <h3 style="margin-bottom:0.75rem;font-size:1rem;padding-bottom:0.5rem;border-bottom:1px solid var(--border);">
                Progress — <?= count($progress) ?>/10 Completed
            </h3>
            <div style="background:var(--bg);border:1px solid var(--border);border-radius:6px;overflow:hidden;margin-bottom:1rem;">
                <div style="height:6px;background:var(--primary);width:<?= (count($progress) / 10 * 100) ?>%;transition:width 0.5s;"></div>
            </div>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Level</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <?php for ($i = 1; $i <= 10; $i++): ?>
                    <tr>
                        <td><?= $i ?></td>
                        <td><a href="level<?= $i ?>.php" style="color:var(--primary);text-decoration:none;"><?= htmlspecialchars($levelNames[$i]) ?></a></td>
                        <td>
                            <?php if (in_array($i, $progress)): ?>
                            <span style="color:#6ee7b7;font-weight:600;">&#10003; Solved</span>
                            <?php else: ?>
                            <span style="color:var(--text-muted);">Pending</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endfor; ?>
                </tbody>
            </table>
            <?php if (count($progress) === 10): ?>
            <div class="message success" style="margin-top:1rem;">
                All 10 levels completed! Excellent work on mastering IDOR and Broken Access Control.
            </div>
            <?php endif; ?>
            <form method="POST" action="submit.php" style="margin-top:1rem;">
                <input type="hidden" name="reset_progress" value="1">
                <button type="submit" class="btn" style="background:var(--danger);color:#fff;font-size:0.8rem;padding:0.3rem 0.75rem;"
                    onclick="return confirm('Reset all progress?')">Reset Progress</button>
            </form>
        </div>
    </div>

</div>

<?php
// Handle progress reset
if (isset($_POST['reset_progress'])) {
    setcookie('idor_lab_progress', '', time() - 3600, '/');
    header('Location: submit.php');
    exit;
}
html_close();
?>
