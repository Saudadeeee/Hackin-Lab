<?php
$levelId    = 8;
$levelTitle = 'Trailing Character Bypass';
$difficulty = 'Hard';

$scenario = <<<'HTML'
<p>The blocklist covers every PHP variant and the check looks solid. But the extension parser and the
web server disagree about where the filename ends.</p>
<p>Exploit that disagreement to smuggle a script through and read
<code>/var/secret/level8_flag.txt</code>.</p>
HTML;

$vulnNote = <<<'HTML'
<strong>Vulnerability:</strong>&nbsp; <code>pathinfo()</code> returns <code>''</code> for <code>shell.php.</code>
and <code>'php '</code> for <code>shell.php </code> &mdash; neither equals <code>'php'</code>, so the blocklist
passes. Apache still runs both as PHP. Normalise (trim trailing dots/spaces) and canonicalise names
before validating, or use an allowlist on a re-generated filename.
HTML;

$sourceCode = <<<'HTML'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level8.php — thorough blocklist defeated by a trailing char</span>
<span class="php-keyword">function</span> <span class="php-function">filter_level8</span>(<span class="php-keyword">array</span> <span class="php-variable">$u</span>): <span class="php-keyword">array</span> {
    <span class="php-variable">$blocked</span> = [<span class="php-string">'php'</span>,<span class="php-string">'php3'</span>,<span class="php-string">'php4'</span>,<span class="php-string">'php5'</span>,<span class="php-string">'php7'</span>,<span class="php-string">'pht'</span>,<span class="php-string">'phtml'</span>,<span class="php-string">'phar'</span>];
<span class="vuln-line">    <span class="php-variable">$ext</span> = <span class="php-function">strtolower</span>(<span class="php-function">pathinfo</span>(<span class="php-variable">$u</span>[<span class="php-string">'name'</span>], <span class="php-keyword">PATHINFO_EXTENSION</span>));  <span class="php-comment">// "shell.php." -&gt; ""</span></span>
    <span class="php-keyword">if</span> (<span class="php-function">in_array</span>(<span class="php-variable">$ext</span>, <span class="php-variable">$blocked</span>, <span class="php-keyword">true</span>)) {
        <span class="php-keyword">return</span> [<span class="php-keyword">false</span>, <span class="php-string">"Rejected: blocklisted extension."</span>];
    }
    <span class="php-keyword">return</span> [<span class="php-keyword">true</span>, <span class="php-string">"Accepted."</span>];   <span class="php-comment">// "shell.php." and "shell.php " both survive</span>
}
HTML;

require __DIR__ . '/render_level.php';
