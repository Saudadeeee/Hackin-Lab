<?php
/**
 * Path Traversal Lab - Helper Functions
 */

function get_flag_for_level(int $levelId): string {
    static $flags = [
        1  => 'FLAG{basic_path_traversal}',
        2  => 'FLAG{lfi_basic_include}',
        3  => 'FLAG{php_filter_wrapper}',
        4  => 'FLAG{double_traverse_bypass}',
        5  => 'FLAG{extension_check_bypass}',
        6  => 'FLAG{log_file_traversal}',
        7  => 'FLAG{base64_filter_exfil}',
        8  => 'FLAG{useless_check_bypass}',
        9  => 'FLAG{proc_self_environ}',
        10 => 'FLAG{multilayer_traversal_master}',
    ];
    return $flags[$levelId] ?? 'FLAG{unknown}';
}

function get_level_hints(int $levelId): array {
    static $hints = [
        1 => [
            'The code appends your input directly to a base path: <code>/var/www/html/files/YOUR_INPUT</code>',
            'The <code>../</code> sequence moves one directory up in a file path.',
            'Count how deep <code>/var/www/html/files/</code> is from the root.',
            'You need to escape 4 directory levels: <code>../../../../</code>',
            'Payload: <code>../../../../var/secret/level1_flag.txt</code>',
        ],
        2 => [
            'The code calls <code>include()</code> directly with user input — no path restriction.',
            'PHP <code>include()</code> can include files from anywhere on the filesystem.',
            'Try including <code>/var/secret/level2_flag.txt</code> directly.',
            'No need for <code>../</code> traversal — just provide an absolute path.',
            'Payload: <code>/var/secret/level2_flag.txt</code>',
        ],
        3 => [
            'The code blocks <code>..</code> but not PHP stream wrappers.',
            '<code>PHP://filter</code> is a built-in wrapper that can read files without <code>..</code>.',
            'The <code>convert.base64-encode</code> filter encodes output as base64.',
            'PHP wrappers use absolute paths so no traversal needed.',
            'Payload: <code>php://filter/convert.base64-encode/resource=/var/secret/level3_flag.txt</code> (then base64 decode the result)',
        ],
        4 => [
            'The code removes <code>../</code> using <code>str_replace</code> — but only non-overlapping matches.',
            'What if you embed <code>../</code> INSIDE another <code>../</code> sequence?',
            'Try: <code>....//</code> — after str_replace removes the inner <code>../</code>, what remains?',
            'Step through: <code>....//</code> → str_replace removes positions 2-4 (<code>../</code>) → result: <code>../</code>!',
            'Payload: <code>....//....//....//....//var/secret/level4_flag.txt</code>',
        ],
        5 => [
            'The code checks that input ends with <code>.txt</code> — but does that prevent traversal?',
            'Path traversal payload <code>../../../../var/secret/level5_flag.txt</code> — does it end with <code>.txt</code>?',
            'The check is: <code>substr($file, -4) !== ".txt"</code> — only checks the EXTENSION!',
            'A path traversal that ends in <code>.txt</code> passes this check completely.',
            'Payload: <code>../../../../var/secret/level5_flag.txt</code>',
        ],
        6 => [
            'The code has LFI — it can read any file including log files.',
            'Log files record request information and persist on the server.',
            'Try to read the server log at <code>/var/log/ptlab/access.log</code>.',
            'The access log contains the flag (pre-poisoned in this lab).',
            'Payload: <code>../../var/log/ptlab/access.log</code>',
        ],
        7 => [
            'The code uses <code>htmlspecialchars()</code> on output but that does not affect file reading.',
            '<code>file_get_contents()</code> supports PHP stream wrappers.',
            'The <code>php://filter</code> wrapper with <code>convert.base64-encode</code> returns base64.',
            'Use an absolute path in the wrapper to bypass the directory check.',
            'Payload: <code>php://filter/convert.base64-encode/resource=/var/secret/level7_flag.txt</code>',
        ],
        8 => [
            'Read the security check carefully: what exactly does it check?',
            'The code checks: <code>substr($path, 0, len($basepath)) !== $basepath</code> — but <code>$path</code> is built from the hardcoded prefix PLUS user input!',
            'Since <code>$path = "/var/www/html/files/" . $file</code>, the substring always starts with the base path.',
            'The security check is completely useless — the prefix is always there. Try path traversal normally.',
            'Payload: <code>../../../../var/secret/level8_flag.txt</code>',
        ],
        9 => [
            'Linux exposes process information in the <code>/proc/</code> virtual filesystem.',
            '<code>/proc/self/environ</code> contains environment variables of the current process.',
            'PHP can read <code>/proc/</code> files using <code>file_get_contents()</code>.',
            'The environment may contain secret values — or try <code>/proc/self/cmdline</code>.',
            'Payload: traverse to <code>/var/secret/level9_flag.txt</code> using <code>../../var/secret/level9_flag.txt</code>. The level flag may also appear in <code>/proc/self/environ</code> if it is set as an env var.',
        ],
        10 => [
            'This level has multiple filters — analyze each one independently first.',
            'Filter 1 removes <code>../</code>. Filter 2 blocks <code>/etc/</code> and <code>/proc/</code>. But NOT <code>/var/secret/</code>!',
            'Use the <code>....//</code> technique to bypass the <code>str_replace("../", "")</code> filter.',
            'Target <code>/var/secret/level10_flag.txt</code> — it is not in the blocked paths <code>/etc/</code> or <code>/proc/</code>.',
            'Payload: <code>....//....//....//....//var/secret/level10_flag.txt</code>',
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

function get_progress(): array {
    $raw = $_COOKIE['pt_lab_progress'] ?? '';
    if (empty($raw)) return [];
    $decoded = json_decode(base64_decode($raw), true);
    return is_array($decoded) ? $decoded : [];
}

function save_progress(array $progress): void {
    $encoded = base64_encode(json_encode($progress));
    setcookie('pt_lab_progress', $encoded, time() + (86400 * 30), '/');
}

function is_level_completed(int $level): bool {
    $progress = get_progress();
    return in_array($level, $progress, true);
}

function mark_level_completed(int $level): void {
    $progress = get_progress();
    if (!in_array($level, $progress, true)) {
        $progress[] = $level;
        save_progress($progress);
    }
}

/**
 * Handle inline flag submission on a level page.
 * Uses the same pt_lab_progress cookie as submit.php.
 *
 * @return array{status: string|null, message: string, already_completed: bool}
 */
function handle_inline_flag_submit(int $levelId): array
{
    $result = ['status' => null, 'message' => '', 'already_completed' => is_level_completed($levelId)];

    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['_flag_submit'])) {
        return $result;
    }

    $flag = trim($_POST['submitted_flag'] ?? '');
    if ($flag === '') {
        $result['status']  = 'error';
        $result['message'] = 'Please enter a flag.';
        return $result;
    }

    if ($flag === get_flag_for_level($levelId)) {
        mark_level_completed($levelId);
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

function get_level_info(): array {
    return [
        1  => ['title' => 'Basic Directory Traversal',            'difficulty' => 'easy',   'badge' => 'Easy',   'desc' => 'Classic path traversal using ../ sequences. No filtering applied — read the source and craft your payload.'],
        2  => ['title' => 'Local File Inclusion without Restriction', 'difficulty' => 'easy', 'badge' => 'Easy', 'desc' => 'Direct LFI with include(). The parameter is passed straight to include() — full filesystem access.'],
        3  => ['title' => 'PHP Filter Wrapper Bypass',             'difficulty' => 'medium', 'badge' => 'Medium', 'desc' => 'The ../ sequence is blocked — but PHP built-in stream wrappers are not. Use php://filter to read files.'],
        4  => ['title' => 'Bypass Single str_replace("../","")',   'difficulty' => 'medium', 'badge' => 'Medium', 'desc' => 'A non-recursive str_replace strips ../ — but nested sequences survive the sanitization.'],
        5  => ['title' => 'Bypass Extension Validation',           'difficulty' => 'medium', 'badge' => 'Medium', 'desc' => 'Only .txt files are "allowed". Identify why this check fails to prevent path traversal.'],
        6  => ['title' => 'Reading Server Log Files via Traversal','difficulty' => 'medium', 'badge' => 'Medium', 'desc' => 'Traverse out of the document root to read a pre-poisoned server log file containing the flag.'],
        7  => ['title' => 'Bypass htmlspecialchars with PHP Wrapper','difficulty' => 'hard', 'badge' => 'Hard',  'desc' => 'Output is encoded with htmlspecialchars. Use a PHP wrapper that returns base64 — encoding sidesteps the escaping.'],
        8  => ['title' => 'Spot the Useless Security Check',       'difficulty' => 'hard',   'badge' => 'Hard',   'desc' => 'There is a "security check" in the code. Read it carefully — is it logically sound? Find the flaw and bypass it.'],
        9  => ['title' => 'Linux /proc Filesystem via Traversal',  'difficulty' => 'hard',   'badge' => 'Hard',   'desc' => 'A blacklist blocks only specific paths. Traverse to /var/secret/ or explore /proc/self/environ for secrets.'],
        10 => ['title' => 'Multi-Filter Path Traversal',           'difficulty' => 'expert', 'badge' => 'Expert', 'desc' => 'Multiple filters are stacked. Analyze each independently and chain bypass techniques to reach the flag.'],
    ];
}
