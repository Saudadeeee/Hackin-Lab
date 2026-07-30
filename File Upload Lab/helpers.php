<?php
/**
 * File Upload Lab - Helper Functions
 *
 * Intentionally-vulnerable teaching lab. Each level accepts an "upload"
 * (a filename + file bytes + claimed Content-Type), applies a progressively
 * stronger validation filter, stores whatever survives under uploads/levelN/,
 * and links to the stored file so a PHP web shell can be browsed for RCE.
 *
 * The per-level FLAG is awarded by verify_upload(), which RE-APPLIES the level's
 * own filter and confirms that an executable PHP payload actually got through.
 */

/* ============================================================
 * Flags
 * ============================================================ */
function get_flag_for_level(int $levelId): string
{
    $flags = [
        1  => 'FLAG{upload_no_validation}',
        2  => 'FLAG{upload_extension_blocklist_bypass}',
        3  => 'FLAG{upload_mime_bypass}',
        4  => 'FLAG{upload_magic_bytes_bypass}',
        5  => 'FLAG{upload_double_extension}',
        6  => 'FLAG{upload_case_bypass}',
        7  => 'FLAG{upload_htaccess}',
        8  => 'FLAG{upload_trailing_bypass}',
        9  => 'FLAG{upload_content_filter_bypass}',
        10 => 'FLAG{upload_waf_bypass}',
    ];
    return $flags[$levelId] ?? '';
}

/* ============================================================
 * Progressive hints (exactly 5 per level, conceptual -> full payload)
 * ============================================================ */
function get_level_hints(int $levelId): array
{
    $hints = [
        1 => [
            'There is <strong>no validation at all</strong>. Whatever filename and bytes you send are stored under <code>uploads/level1/</code> and served back by Apache.',
            'PHP files inside the web root are <em>executed</em> by the server, not shown as text. Give your file a <code>.php</code> extension.',
            'Put PHP code between tags: <code>&lt;?php /* code */ ?&gt;</code>. A tiny web shell can read files or run shell commands.',
            'The flag is baked on the server at <code>/var/secret/level1_flag.txt</code>. Read it with <code>&lt;?php readfile(\'/var/secret/level1_flag.txt\'); ?&gt;</code> or <code>system(\'cat ...\')</code>.',
            'Working: filename <code>shell.php</code>, content <code>&lt;?php readfile(\'/var/secret/level1_flag.txt\'); ?&gt;</code>. Submit it, then click the stored-file link to run it. The panel also awards the flag the moment it detects executable PHP that passed the filter.',
        ],
        2 => [
            'The filter uses an <strong>extension blocklist</strong>. Read exactly which extension(s) it rejects &mdash; it only blocks <code>.php</code>.',
            'A blocklist is only as good as its list. Apache executes far more than just <code>.php</code>.',
            'Extensions such as <code>.phtml</code>, <code>.php5</code>, and <code>.pht</code> are also handled as PHP but are missing from the list.',
            'Keep your PHP content identical &mdash; just change the extension to one that survives the blocklist.',
            'Working: filename <code>shell.phtml</code> (or <code>shell.php5</code> / <code>shell.pht</code>), content <code>&lt;?php system(\'cat /var/secret/level2_flag.txt\'); ?&gt;</code>.',
        ],
        3 => [
            'This filter checks the upload\'s <strong>Content-Type (MIME)</strong> header and requires <code>image/png</code>.',
            'The Content-Type is chosen by the <em>client</em>. It is metadata attached to the request &mdash; it is not derived from the actual bytes, so it can be forged.',
            'Set the claimed Content-Type to <code>image/png</code> while still uploading a <code>.php</code> file full of PHP.',
            'In this lab, edit the <em>Content-Type</em> field to <code>image/png</code>. With a real tool (curl/Burp) you would set the multipart part header <code>Content-Type: image/png</code>.',
            'Working: filename <code>shell.php</code>, Content-Type <code>image/png</code>, content <code>&lt;?php readfile(\'/var/secret/level3_flag.txt\'); ?&gt;</code>.',
        ],
        4 => [
            'The filter reads the first bytes (the <strong>magic bytes</strong>) to confirm the file is a real image before accepting it.',
            'A single file can start with a valid image signature <em>and</em> still contain PHP after it &mdash; that is a <strong>polyglot</strong>.',
            'GIF images begin with the ASCII bytes <code>GIF89a</code>. Prepend that string to the front of your PHP.',
            'Keep the <code>.php</code> extension so Apache still executes the file; the magic-byte check only inspects the beginning of the content.',
            'Working: filename <code>shell.php</code>, content <code>GIF89a;&lt;?php readfile(\'/var/secret/level4_flag.txt\'); ?&gt;</code>.',
        ],
        5 => [
            'The filter only inspects the <strong>last</strong> extension and compares it to an image whitelist (<code>jpg/jpeg/png/gif</code>).',
            'Apache\'s <code>mod_mime</code> will execute a file if <em>any</em> extension in the name maps to PHP &mdash; not just the final one.',
            '<code>shell.php.jpg</code> ends in <code>.jpg</code> (which passes the whitelist), but the embedded <code>.php</code> makes Apache run it as PHP.',
            'Give the file two extensions: put <code>.php</code> before an allowed image extension.',
            'Working: filename <code>shell.php.jpg</code>, content <code>&lt;?php readfile(\'/var/secret/level5_flag.txt\'); ?&gt;</code>. (If a filter instead checks only the <em>first</em> extension, <code>shell.jpg.php</code> is the bypass.)',
        ],
        6 => [
            'The blocklist here is thorough (<code>php, phtml, php3, php4, php5, pht, phar</code>) &mdash; but the comparison is <strong>case-sensitive</strong>.',
            'Look closely: <code>end(explode(\'.\', $name))</code> is compared to the list <em>without</em> lowercasing it first.',
            'The filesystem and Apache treat <code>.PhP</code> exactly like <code>.php</code>, yet the mixed-case string is not present in the lowercase blocklist.',
            'Change the case of the extension so it no longer string-matches any blocklist entry.',
            'Working: filename <code>shell.PhP</code>, content <code>&lt;?php readfile(\'/var/secret/level6_flag.txt\'); ?&gt;</code>.',
        ],
        7 => [
            'Every PHP-ish extension is blocked, so you cannot upload a script directly. Instead, change how Apache <em>interprets</em> other files.',
            'Apache reads per-directory <code>.htaccess</code> files. If you can upload one into the upload directory, you control the handler rules there.',
            'Step 1: upload a file named <code>.htaccess</code> that maps a harmless extension (e.g. <code>.jpg</code>) to the PHP handler.',
            'Step 2: upload <code>shell.jpg</code> containing PHP &mdash; it now executes because your <code>.htaccess</code> re-mapped <code>.jpg</code> to PHP.',
            'Working: (1) filename <code>.htaccess</code>, content <code>&lt;FilesMatch "\.jpg$"&gt;<br>SetHandler application/x-httpd-php<br>&lt;/FilesMatch&gt;</code> &nbsp; (2) filename <code>shell.jpg</code>, content <code>&lt;?php readfile(\'/var/secret/level7_flag.txt\'); ?&gt;</code>. The panel awards the flag as soon as a PHP-mapping <code>.htaccess</code> is accepted.',
        ],
        8 => [
            'The blocklist covers all PHP variants, but the extension <em>parser</em> can be tricked by a trailing character.',
            '<code>pathinfo(\'shell.php.\', PATHINFO_EXTENSION)</code> returns <code>\'\'</code>, and <code>pathinfo(\'shell.php \', ...)</code> returns <code>\'php \'</code> &mdash; neither equals <code>\'php\'</code>.',
            'Apache, however, still runs <code>shell.php.</code> and <code>shell.php </code> (trailing space) as PHP.',
            'Append a single trailing dot or a trailing space after <code>.php</code>.',
            'Working: filename <code>shell.php.</code> (or <code>shell.php </code> with a trailing space), content <code>&lt;?php readfile(\'/var/secret/level8_flag.txt\'); ?&gt;</code>.',
        ],
        9 => [
            'This filter scans the file <strong>content</strong> and rejects anything containing the string <code>&lt;?php</code>.',
            'PHP has more than one opening tag. The short-echo tag <code>&lt;?=</code> is always enabled (independent of <code>short_open_tag</code>) and executes code.',
            'Note: <code>&lt;script language="php"&gt;</code> was removed in PHP 7 and no longer executes &mdash; so rely on <code>&lt;?=</code> here.',
            'Rewrite your payload to open with <code>&lt;?=</code> instead of <code>&lt;?php</code>, and keep a <code>.php</code> filename.',
            'Working: filename <code>shell.php</code>, content <code>&lt;?= readfile(\'/var/secret/level9_flag.txt\'); ?&gt;</code>.',
        ],
        10 => [
            'Four checks are stacked: (1) last-extension blocklist, (2) <code>image/png</code> MIME, (3) image magic bytes, (4) a <code>&lt;?php</code> content scan. Exactly one payload beats all four at once.',
            'Beat the extension blocklist with a <strong>double extension</strong> &mdash; <code>shell.php.jpg</code>, whose last extension is <code>jpg</code>.',
            'Beat the MIME check by claiming <code>image/png</code>; beat the magic-byte check by starting the content with <code>GIF89a</code>.',
            'Beat the content scan by using <code>&lt;?=</code> instead of <code>&lt;?php</code>.',
            'Working: filename <code>shell.php.jpg</code>, Content-Type <code>image/png</code>, content <code>GIF89a;&lt;?= readfile(\'/var/secret/level10_flag.txt\'); ?&gt;</code>.',
        ],
    ];
    return $hints[$levelId] ?? [];
}

/**
 * Renders a progressive hint section with a "Show Next Hint" button.
 * (Verbatim from the XSS Lab golden reference.)
 */
function render_hint_section(array $hints, string $title = 'Hints'): string
{
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
    <?php
    if (!$scriptRendered) {
        $scriptRendered = true;
        ?>
        <script>
        document.addEventListener('click', function(e) {
            if (!e.target.classList.contains('hint-btn')) return;
            const targetId = e.target.getAttribute('data-hint-target');
            const container = document.getElementById(targetId);
            const items = container.querySelectorAll('.hint-item[hidden]');
            const total = container.querySelectorAll('.hint-item').length;
            if (items.length > 0) {
                items[0].removeAttribute('hidden');
                const shown = total - items.length + 1;
                e.target.textContent = shown < total ? 'Show Next Hint (' + shown + '/' + total + ')' : 'All hints shown';
                if (shown >= total) e.target.disabled = true;
            }
        });
        </script>
        <?php
    }
    return ob_get_clean();
}

/* ============================================================
 * Upload storage helpers  (uploads stay inside the lab dir)
 * ============================================================ */
function upload_base_dir(): string
{
    return __DIR__ . '/uploads';
}

function ensure_upload_dir(int $level): string
{
    $dir = upload_base_dir() . '/level' . $level;
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
    }
    return $dir;
}

/**
 * Strip directory-escape characters but PRESERVE extension tricks
 * (leading dots for .htaccess, trailing dot/space, double extensions).
 * Returns '' for names that cannot be stored safely.
 */
function sanitize_store_name(string $name): string
{
    $name = str_replace(["\0", "/", "\\"], '', $name);
    // Reject pure traversal / empty markers, but allow dotfiles like .htaccess
    if ($name === '' || $name === '.' || $name === '..') {
        return '';
    }
    return $name;
}

/**
 * Store the uploaded bytes under uploads/levelN/. Returns the web-relative
 * path for linking, or null on failure. The file is made world-readable so
 * Apache can serve/execute it (intentional for the lab).
 */
function store_upload(int $level, string $name, string $content): ?string
{
    $store = sanitize_store_name($name);
    if ($store === '') return null;

    $dir  = ensure_upload_dir($level);
    $path = $dir . '/' . $store;

    if (@file_put_contents($path, $content) === false) {
        return null;
    }
    @chmod($path, 0644);

    return 'uploads/level' . $level . '/' . rawurlencode($store);
}

/* ============================================================
 * "Would Apache execute this?" helpers
 * ============================================================ */

/**
 * Matches the Apache handler config baked in the Dockerfile:
 * any php-family extension, even when followed by a trailing dot/space or
 * another extension (double extension).
 */
function name_executes_as_php(string $name): bool
{
    return (bool) preg_match('/\.(php|php3|php4|php5|php7|pht|phtml|phar)([. ]|$)/i', $name);
}

/** Contains a PHP tag that actually executes (long tag or short-echo tag). */
function has_php_code(string $content): bool
{
    return stripos($content, '<?php') !== false || strpos($content, '<?=') !== false;
}

/** Short-echo tag only (used when <?php is blocked by content filters). */
function has_short_echo_tag(string $content): bool
{
    return strpos($content, '<?=') !== false;
}

/** True when the bytes begin with a recognised image signature. */
function has_image_magic(string $content): bool
{
    return substr($content, 0, 6) === 'GIF89a'
        || substr($content, 0, 6) === 'GIF87a'
        || substr($content, 0, 8) === "\x89PNG\r\n\x1a\n"
        || substr($content, 0, 3) === "\xff\xd8\xff";
}

/** True when a .htaccess payload maps some extension to the PHP handler. */
function htaccess_maps_php(string $name, string $content): bool
{
    if (strtolower(sanitize_store_name($name)) !== '.htaccess') {
        return false;
    }
    return (bool) preg_match('/(AddType|AddHandler|SetHandler)\s+[^\n]*(x-httpd-php|php-script|php)/i', $content)
        || (bool) preg_match('/php_value|php_flag|php_admin_/i', $content);
}

/* ============================================================
 * Per-level validation filters
 * Each returns [bool $accepted, string $reason].
 * The bodies shown in each level's "Vulnerable Source Code" panel MATCH these.
 * ============================================================ */

function filter_level1(array $u): array
{
    // No validation whatsoever.
    return [true, 'Accepted - no validation applied.'];
}

function filter_level2(array $u): array
{
    $blocked = ['php'];
    $ext = strtolower(pathinfo($u['name'], PATHINFO_EXTENSION));
    if (in_array($ext, $blocked, true)) {
        return [false, "Rejected: extension .$ext is blocklisted."];
    }
    return [true, "Accepted: extension .$ext is not blocklisted."];
}

function filter_level3(array $u): array
{
    if (($u['mime'] ?? '') !== 'image/png') {
        return [false, "Rejected: Content-Type must be image/png (got '" . ($u['mime'] ?? '') . "')."];
    }
    return [true, 'Accepted: Content-Type is image/png.'];
}

function filter_level4(array $u): array
{
    if (!has_image_magic($u['content'])) {
        return [false, 'Rejected: file does not start with a valid image signature (magic bytes).'];
    }
    return [true, 'Accepted: valid image magic bytes detected at start of file.'];
}

function filter_level5(array $u): array
{
    $allowed = ['jpg', 'jpeg', 'png', 'gif'];
    $ext = strtolower(pathinfo($u['name'], PATHINFO_EXTENSION));
    if (!in_array($ext, $allowed, true)) {
        return [false, "Rejected: final extension .$ext is not an allowed image type."];
    }
    return [true, "Accepted: final extension .$ext is a whitelisted image type."];
}

function filter_level6(array $u): array
{
    $blocked = ['php', 'php3', 'php4', 'php5', 'php7', 'pht', 'phtml', 'phar'];
    $parts = explode('.', $u['name']);
    $ext   = end($parts);                 // BUG: not lowercased -> case-sensitive compare
    if (in_array($ext, $blocked, true)) {
        return [false, "Rejected: extension .$ext is blocklisted."];
    }
    return [true, "Accepted: extension .$ext is not blocklisted."];
}

function filter_level7(array $u): array
{
    $blocked = ['php', 'php3', 'php4', 'php5', 'php7', 'pht', 'phtml', 'phar'];
    $ext = strtolower(pathinfo($u['name'], PATHINFO_EXTENSION));
    if (in_array($ext, $blocked, true)) {
        return [false, "Rejected: script extension .$ext is blocklisted."];
    }
    return [true, "Accepted: .$ext (config/image files are permitted)."];
}

function filter_level8(array $u): array
{
    $blocked = ['php', 'php3', 'php4', 'php5', 'php7', 'pht', 'phtml', 'phar'];
    $ext = strtolower(pathinfo($u['name'], PATHINFO_EXTENSION));
    if (in_array($ext, $blocked, true)) {
        return [false, "Rejected: extension .$ext is blocklisted."];
    }
    return [true, "Accepted: parsed extension '.$ext' is not blocklisted."];
}

function filter_level9(array $u): array
{
    if (stripos($u['content'], '<?php') !== false) {
        return [false, 'Rejected: file content contains a <?php tag.'];
    }
    return [true, 'Accepted: no <?php tag found in file content.'];
}

function filter_level10(array $u): array
{
    // Layer 1: last-extension blocklist (case-insensitive)
    $blocked = ['php', 'php3', 'php4', 'php5', 'php7', 'pht', 'phtml', 'phar'];
    $ext = strtolower(pathinfo($u['name'], PATHINFO_EXTENSION));
    if (in_array($ext, $blocked, true)) {
        return [false, "Rejected [Layer 1 / extension]: .$ext is blocklisted."];
    }
    // Layer 2: MIME must be image/png
    if (($u['mime'] ?? '') !== 'image/png') {
        return [false, 'Rejected [Layer 2 / MIME]: Content-Type must be image/png.'];
    }
    // Layer 3: magic bytes must be an image
    if (!has_image_magic($u['content'])) {
        return [false, 'Rejected [Layer 3 / magic bytes]: not a valid image.'];
    }
    // Layer 4: content must not contain <?php
    if (stripos($u['content'], '<?php') !== false) {
        return [false, 'Rejected [Layer 4 / content]: contains a <?php tag.'];
    }
    return [true, 'Accepted: survived all four filter layers.'];
}

/* ============================================================
 * The authoritative flag gate.
 *
 * Re-applies the level's own filter and confirms that what survived is an
 * EXECUTABLE PHP payload (right kind of filename AND a working PHP tag).
 * Never string-matches the flag.
 * ============================================================ */
function verify_upload(int $level, string $name, string $content, string $mime = ''): bool
{
    if ($level < 1 || $level > 10) return false;

    $u = ['name' => $name, 'content' => $content, 'mime' => $mime];

    // Level 7 is exploited by a malicious .htaccess (the "payload" that grants execution).
    if ($level === 7) {
        [$accepted] = filter_level7($u);
        return $accepted && htaccess_maps_php($name, $content);
    }

    [$accepted] = call_user_func('filter_level' . $level, $u);
    if (!$accepted) return false;

    // Whatever survived must be a filename Apache runs as PHP...
    if (!name_executes_as_php($name)) return false;

    // ...and must contain a PHP tag that executes.
    if ($level === 9 || $level === 10) {
        // <?php is blocked here, so a surviving payload must use the short-echo tag.
        return has_short_echo_tag($content);
    }
    return has_php_code($content);
}

/**
 * Normalise a request into an "uploaded file" tuple.
 * Supports a real multipart file (advanced tools) OR the in-browser
 * craft fields (fname / fcontent / fmime) so every bypass is solvable
 * from a plain browser with no external tooling.
 *
 * @return array{name:string,content:string,mime:string,source:string}|null
 */
function get_upload_input(): ?array
{
    // 1) A genuine multipart upload (curl / Burp / <input type=file>).
    if (isset($_FILES['file']) && is_array($_FILES['file'])
        && ($_FILES['file']['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_OK
        && is_uploaded_file($_FILES['file']['tmp_name'] ?? '')) {
        return [
            'name'    => (string) ($_FILES['file']['name'] ?? ''),
            'content' => (string) @file_get_contents($_FILES['file']['tmp_name']),
            'mime'    => (string) ($_FILES['file']['type'] ?? 'application/octet-stream'),
            'source'  => 'file',
        ];
    }

    // 2) In-browser crafted upload.
    if (isset($_POST['fname']) || isset($_POST['fcontent'])) {
        $name    = (string) ($_POST['fname'] ?? '');
        $content = (string) ($_POST['fcontent'] ?? '');
        $mime    = (string) ($_POST['fmime'] ?? 'application/octet-stream');
        if (trim($name) === '' && $content === '') {
            return null; // empty submission -> do not process (no fatal)
        }
        return ['name' => $name, 'content' => $content, 'mime' => $mime, 'source' => 'craft'];
    }

    return null;
}

/* ============================================================
 * Inline flag submission + central-submit progress cookie
 * (mirrors XSS Lab; only the cookie name differs)
 * ============================================================ */
function handle_inline_flag_submit(int $levelId): array
{
    $result = ['status' => null, 'message' => '', 'already_completed' => false];

    $completed = [];
    if (!empty($_COOKIE['upload_lab_progress'])) {
        $decoded = json_decode($_COOKIE['upload_lab_progress'], true);
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

    if ($flag === get_flag_for_level($levelId)) {
        if (!in_array($levelId, $completed)) {
            $completed[] = $levelId;
            sort($completed);
            setcookie('upload_lab_progress', json_encode($completed), time() + 86400 * 30, '/');
        }
        $result['status']            = 'success';
        $result['message']           = 'Correct! Flag accepted.';
        $result['already_completed'] = true;
    } else {
        $result['status']  = 'error';
        $result['message'] = 'Incorrect flag. Keep trying!';
    }

    return $result;
}

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
