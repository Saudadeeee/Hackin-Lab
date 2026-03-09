<?php
declare(strict_types=1);

/**
 * SQLi Lab Helper Functions
 */

/**
 * Handle inline flag submission on a level page.
 * Verifies flag against MySQL `levels` table, same as submit.php.
 * Uses the `completed_levels` cookie shared with submit.php.
 *
 * @return array{status: string|null, message: string, already_completed: bool}
 */
function handle_inline_flag_submit(int $levelId): array
{
    $result = ['status' => null, 'message' => '', 'already_completed' => false];

    // Load progress from cookie (same cookie as submit.php)
    $completed = [];
    if (!empty($_COOKIE['completed_levels'])) {
        $decoded = json_decode($_COOKIE['completed_levels'], true);
        if (is_array($decoded)) $completed = $decoded;
    }
    $result['already_completed'] = in_array($levelId, $completed);

    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['_flag_submit'])) {
        return $result;
    }

    $flag = trim($_POST['submitted_flag'] ?? '');
    if ($flag === '') {
        $result['status']  = 'error';
        $result['message'] = 'Please enter a flag.';
        return $result;
    }

    // Verify against MySQL (same credential lookup order as submit.php)
    $host   = $_ENV['FLAG_DB_HOST'] ?? ($_ENV['DB_HOST'] ?? 'db');
    $user   = $_ENV['FLAG_DB_USER'] ?? ($_ENV['DB_USER'] ?? 'webapp');
    $pass   = $_ENV['FLAG_DB_PASS'] ?? ($_ENV['DB_PASS'] ?? 'webapp123');
    $dbname = $_ENV['DB_NAME'] ?? 'sqli_lab';

    try {
        $conn = new mysqli($host, $user, $pass, $dbname);
        if ($conn->connect_error) {
            $result['status']  = 'error';
            $result['message'] = 'Database connection error.';
            return $result;
        }
        $stmt = $conn->prepare('SELECT flag FROM levels WHERE id = ?');
        if (!$stmt) {
            $conn->close();
            $result['status']  = 'error';
            $result['message'] = 'Verification error.';
            return $result;
        }
        $stmt->bind_param('i', $levelId);
        $stmt->execute();
        $stmt->bind_result($correctFlag);
        $stmt->fetch();
        $stmt->close();
        $conn->close();

        if ($correctFlag !== null && $flag === $correctFlag) {
            if (!in_array($levelId, $completed)) {
                $completed[] = $levelId;
                sort($completed);
                setcookie('completed_levels', json_encode($completed), time() + 86400 * 30, '/');
            }
            $result['status']            = 'success';
            $result['message']           = 'Correct! Flag accepted.';
            $result['already_completed'] = true;
        } else {
            $result['status']  = 'error';
            $result['message'] = 'Incorrect flag. Keep trying!';
        }
    } catch (Exception $e) {
        $result['status']  = 'error';
        $result['message'] = 'Verification error.';
    }

    return $result;
}

/**
 * Render the compact inline flag submit form.
 *
 * @param array{status: string|null, message: string, already_completed: bool} $result
 */
function render_inline_flag_form(int $levelId, array $result): string
{
    $status           = $result['status'] ?? null;
    $message          = $result['message'] ?? '';
    $alreadyCompleted = $result['already_completed'] ?? false;

    ob_start();
    ?>
    <div class="inline-flag-submit">
        <h3>Submit Flag</h3>
        <div class="form-inner">
            <?php if ($status === 'success'): ?>
                <div class="message success"><?= htmlspecialchars($message) ?> &mdash; <a href="submit.php">view all progress &rarr;</a></div>
            <?php elseif ($status === 'error'): ?>
                <div class="message error"><?= htmlspecialchars($message) ?></div>
            <?php endif; ?>
            <?php if ($alreadyCompleted && $status !== 'success'): ?>
                <div class="message info">Level <?= (int)$levelId ?> already completed. <a href="submit.php">View progress &rarr;</a></div>
            <?php endif; ?>
            <?php if (!$alreadyCompleted || $status === 'error'): ?>
            <form method="POST" action="">
                <input type="hidden" name="_flag_submit" value="1">
                <div class="inline-flag-row">
                    <input type="text" name="submitted_flag" class="form-control"
                           placeholder="FLAG{...}" autocomplete="off" spellcheck="false"
                           value="<?= htmlspecialchars($_POST['submitted_flag'] ?? '') ?>">
                    <button type="submit" class="btn">Check</button>
                </div>
            </form>
            <?php endif; ?>
        </div>
    </div>
    <?php
    return ob_get_clean();
}
