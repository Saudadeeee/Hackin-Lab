<?php
$levelId    = 5;
$levelTitle = 'Double Extension Bypass';
$difficulty = 'Medium';

$scenario = <<<'HTML'
<p>The uploader now uses an allowlist &mdash; but it only inspects the <strong>last</strong> extension
of the filename and requires an image type (<code>jpg/jpeg/png/gif</code>).</p>
<p>Apache decides how to run a file differently. Abuse that gap and read
<code>/var/secret/level5_flag.txt</code>.</p>
HTML;

$vulnNote = <<<'HTML'
<strong>Vulnerability:</strong>&nbsp; Apache's <code>mod_mime</code> executes a file if <em>any</em>
extension maps to PHP. <code>shell.php.jpg</code> ends in <code>.jpg</code> (passing the allowlist) but the
embedded <code>.php</code> makes it run as PHP. Validate the whole filename, not just the final segment.
HTML;

$sourceCode = <<<'HTML'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level5.php — allowlist checks only the final extension</span>
<span class="php-keyword">function</span> <span class="php-function">filter_level5</span>(<span class="php-keyword">array</span> <span class="php-variable">$u</span>): <span class="php-keyword">array</span> {
    <span class="php-variable">$allowed</span> = [<span class="php-string">'jpg'</span>, <span class="php-string">'jpeg'</span>, <span class="php-string">'png'</span>, <span class="php-string">'gif'</span>];
    <span class="php-variable">$ext</span> = <span class="php-function">strtolower</span>(<span class="php-function">pathinfo</span>(<span class="php-variable">$u</span>[<span class="php-string">'name'</span>], <span class="php-keyword">PATHINFO_EXTENSION</span>));  <span class="php-comment">// last ext only</span>
<span class="vuln-line">    <span class="php-keyword">if</span> (!<span class="php-function">in_array</span>(<span class="php-variable">$ext</span>, <span class="php-variable">$allowed</span>, <span class="php-keyword">true</span>)) {           <span class="php-comment">// shell.php.jpg -> "jpg" -> OK</span></span>
        <span class="php-keyword">return</span> [<span class="php-keyword">false</span>, <span class="php-string">"Rejected: not an allowed image extension."</span>];
    }
    <span class="php-keyword">return</span> [<span class="php-keyword">true</span>, <span class="php-string">"Accepted: final extension is whitelisted."</span>];
}
HTML;

require __DIR__ . '/render_level.php';
