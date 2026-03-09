<?php
function get_flag_for_level(int $levelId): string {
    static $flags = [
        1  => 'FLAG{basic_idor_object_reference}',
        2  => 'FLAG{idor_file_download}',
        3  => 'FLAG{hidden_parameter_idor}',
        4  => 'FLAG{horizontal_privilege_escalation}',
        5  => 'FLAG{mass_assignment_role}',
        6  => 'FLAG{cookie_role_forgery}',
        7  => 'FLAG{api_idor_no_ownership}',
        8  => 'FLAG{predictable_reset_token}',
        9  => 'FLAG{jwt_no_signature_verify}',
        10 => 'FLAG{idor_race_condition_bypass}',
    ];
    return $flags[$levelId] ?? 'FLAG{unknown}';
}

function get_level_hints(int $levelId): array {
    static $hints = [
        1 => [
            'The code fetches a document by <code>id</code> from the GET parameter.',
            'There is no check: <em>"Does this document belong to the logged-in user?"</em>',
            'Try different document IDs: 1, 2, 3, 4, 5...',
            'Document ID 4 belongs to the admin and contains the flag.',
            'Payload: <code>?id=4</code>',
        ],
        2 => [
            'The download endpoint takes a <code>filename</code> GET parameter.',
            'The code reads from the uploads table by filename without checking ownership.',
            'Try other uploaded filenames you did not upload yourself.',
            'The file with name <code>bob_report.txt</code> contains the flag.',
            'Payload: <code>?filename=bob_report.txt</code> while logged in as alice (session id=1)',
        ],
        3 => [
            'Look at the HTML form source — is there a hidden field you can modify?',
            'The form has a <code>user_id</code> field that is sent with POST.',
            'The server uses this field as the user identity without re-validating.',
            'Change the <code>user_id</code> to 4 (admin) to fetch admin profile data.',
            'Edit the input value to 4 and submit the form to get admin profile.',
        ],
        4 => [
            'The session stores <code>user_id</code> after login. The code uses it to fetch messages.',
            'But the code does not verify: <em>"Is this message actually addressed to me?"</em>',
            'Try fetching messages with different <code>msg_id</code> values.',
            'Message ID 2 from admin to bob contains the flag.',
            'Payload: <code>?msg_id=2</code> (while any user is "logged in")',
        ],
        5 => [
            'The registration/update form sends a POST request with user fields.',
            'Read the code: what POST parameters does the server accept?',
            'The server directly binds all POST fields to the UPDATE query — including <code>role</code>.',
            'Adding <code>role=admin</code> to the POST request escalates your privilege.',
            'In browser DevTools Console: <code>fetch("/level5.php", {method:"POST", body: new URLSearchParams({username:"testuser", email:"x@x.com", role:"admin"})})</code>',
        ],
        6 => [
            'The server reads the user role from a cookie called <code>user_role</code>.',
            'No server-side session or signature validates this cookie.',
            'Changing the cookie value from <code>user</code> to <code>admin</code> grants admin access.',
            'In browser DevTools → Application → Cookies → edit <code>user_role</code> to <code>admin</code>.',
            'Or: <code>document.cookie = "user_role=admin"</code> in browser console, then refresh.',
        ],
        7 => [
            'The API endpoint fetches user data based on <code>id</code> in the JSON body.',
            'The endpoint checks if the API key is valid — but does not check WHOSE data is being accessed.',
            'Any valid API key can fetch any user\'s data by changing the <code>id</code> field.',
            'Use alice\'s API key (<code>key_alice_abc123</code>) but request <code>id: 4</code> (admin).',
            'Payload: POST to <code>/api.php?action=getUser</code> with JSON body <code>{"api_key":"key_alice_abc123","id":4}</code>',
        ],
        8 => [
            'The password reset sends a token via URL. Look at how the token is generated in the code.',
            'The code generates the token as <code>md5($username)</code> — fully predictable!',
            'You know the username <code>admin</code> — so compute: <code>md5("admin")</code>.',
            '<code>md5("admin")</code> = <code>21232f297a57a5a743894a0e4a801fc3</code>',
            'Submit that token as the reset token: <code>?user=admin&token=21232f297a57a5a743894a0e4a801fc3</code>',
        ],
        9 => [
            'The token is a JWT (JSON Web Token) — it has 3 parts separated by dots.',
            'The code decodes and uses the payload WITHOUT verifying the signature!',
            'A JWT has 3 base64-encoded parts: header.payload.signature.',
            'Decode the payload (middle part), change <code>"role":"user"</code> to <code>"role":"admin"</code>, re-encode it.',
            'Forge a token: keep the same header, modify payload, use any fake signature. Submit as cookie <code>token</code>.',
        ],
        10 => [
            'The code creates a temporary resource and then immediately deletes it.',
            'There is a tiny window between creation and deletion — a race condition.',
            'Send many rapid requests simultaneously to hit the window before deletion.',
            'Use multiple concurrent HTTP requests using curl, Python threads, or browser tabs.',
            'Try: First create a reward for user 1 (alice), then claim it as user 2 (bob).',
        ],
    ];
    return $hints[$levelId] ?? [];
}

function render_hint_section(array $hints, string $title = 'Hints'): string {
    if (empty($hints)) return '';
    static $scriptRendered = false;
    $id = uniqid('hint_', false);
    ob_start();
    ?>
    <div class="hints" id="<?= $id ?>">
        <h3><?= htmlspecialchars($title) ?></h3>
        <button class="hint-btn" data-hint-target="<?= $id ?>">Show Next Hint (0/<?= count($hints) ?>)</button>
        <ul class="hint-list">
            <?php foreach ($hints as $hint): ?>
            <li class="hint-item" hidden><?= $hint ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
    <?php if (!$scriptRendered) { $scriptRendered = true; ?>
    <script>
    document.addEventListener('click', function(e) {
        if (!e.target.classList.contains('hint-btn')) return;
        const id = e.target.getAttribute('data-hint-target');
        const container = document.getElementById(id);
        const hidden = container.querySelectorAll('.hint-item[hidden]');
        const total = container.querySelectorAll('.hint-item').length;
        if (hidden.length > 0) {
            hidden[0].removeAttribute('hidden');
            const shown = total - hidden.length + 1;
            e.target.textContent = shown < total ? 'Show Next Hint (' + shown + '/' + total + ')' : 'All hints shown';
            if (shown >= total) e.target.disabled = true;
        }
    });
    </script>
    <?php } return ob_get_clean();
}

function get_fake_session_user(): array {
    // Simulated logged-in user (alice) for challenges that need a "current user" context
    return ['id' => 1, 'username' => 'alice', 'role' => 'user'];
}

function render_page_header(string $title, string $subtitle, int $level, int $totalLevels = 10): void {
    $prevLink = $level > 1 ? '<a href="level' . ($level - 1) . '.php" class="prev-link">&larr; Level ' . ($level - 1) . '</a>' : '';
    $nextLink = $level < $totalLevels ? '<a href="level' . ($level + 1) . '.php" class="next-link">Level ' . ($level + 1) . ' &rarr;</a>' : '';
    ?>
    <div class="header">
        <div>
            <h1><?= htmlspecialchars($title) ?></h1>
            <p><?= htmlspecialchars($subtitle) ?></p>
        </div>
        <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;">
            <a href="index.php" class="back-btn">&#8592; Lab Home</a>
            <?= $prevLink ?>
            <?= $nextLink ?>
            <a href="submit.php" class="submit-btn">Submit Flag</a>
        </div>
    </div>
    <?php
}

function html_open(string $title): void {
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= htmlspecialchars($title) ?> — IDOR Lab</title>
<link rel="stylesheet" href="css/styles.css">
</head>
<body>
<div class="container">
    <?php
}

function html_close(): void {
    ?>
</div>
</body>
</html>
    <?php
}

/**
 * Handle inline flag submission on a level page.
 * Uses the same idor_lab_progress cookie (base64+JSON) as submit.php.
 *
 * @return array{status: string|null, message: string, already_completed: bool}
 */
function handle_inline_flag_submit(int $levelId): array
{
    $result = ['status' => null, 'message' => '', 'already_completed' => false];

    $progress = [];
    $rawCookie = $_COOKIE['idor_lab_progress'] ?? '';
    if ($rawCookie) {
        $decoded = json_decode(base64_decode($rawCookie), true);
        if (is_array($decoded)) $progress = $decoded;
    }
    $result['already_completed'] = in_array($levelId, $progress);

    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['_flag_submit'])) {
        return $result;
    }

    $flag = trim($_POST['submitted_flag'] ?? '');
    if ($flag === '') {
        $result['status']  = 'error';
        $result['message'] = 'Please enter a flag.';
        return $result;
    }

    if (strcasecmp($flag, get_flag_for_level($levelId)) === 0) {
        if (!in_array($levelId, $progress)) {
            $progress[] = $levelId;
            sort($progress);
            $encoded = base64_encode(json_encode($progress));
            setcookie('idor_lab_progress', $encoded, time() + 86400 * 30, '/');
        }
        $result['status']           = 'success';
        $result['message']          = 'Correct! Flag accepted.';
        $result['already_completed'] = true;
    } else {
        $result['status']  = 'error';
        $result['message'] = 'Incorrect flag. Keep trying!';
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
                    <button type="submit" class="btn btn-primary">Check</button>
                </div>
            </form>
            <?php endif; ?>
        </div>
    </div>
    <?php
    return ob_get_clean();
}
