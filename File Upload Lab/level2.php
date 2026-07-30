<?php
$levelId    = 2;
$levelTitle = 'Extension Blocklist Bypass';
$difficulty = 'Easy';

$scenario = <<<'HTML'
<p>The uploader now rejects <code>.php</code> files using a blocklist. But a blocklist is only as good
as its list &mdash; and this one is short.</p>
<p>Find another extension that Apache still executes as PHP and read
<code>/var/secret/level2_flag.txt</code>.</p>
HTML;

$vulnNote = <<<'HTML'
<strong>Vulnerability:</strong>&nbsp; The blocklist only contains <code>php</code>. Apache also executes
<code>.phtml</code>, <code>.php5</code>, <code>.pht</code> and other variants, none of which are blocked.
Blocklists are inherently incomplete &mdash; prefer an allowlist.
HTML;

$sourceCode = <<<'HTML'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level2.php — extension blocklist (blocklist &lt; allowlist)</span>
<span class="php-keyword">function</span> <span class="php-function">filter_level2</span>(<span class="php-keyword">array</span> <span class="php-variable">$u</span>): <span class="php-keyword">array</span> {
    <span class="php-variable">$blocked</span> = [<span class="php-string">'php'</span>];
    <span class="php-variable">$ext</span> = <span class="php-function">strtolower</span>(<span class="php-function">pathinfo</span>(<span class="php-variable">$u</span>[<span class="php-string">'name'</span>], <span class="php-keyword">PATHINFO_EXTENSION</span>));
<span class="vuln-line">    <span class="php-keyword">if</span> (<span class="php-function">in_array</span>(<span class="php-variable">$ext</span>, <span class="php-variable">$blocked</span>, <span class="php-keyword">true</span>)) {           <span class="php-comment">// only blocks .php</span></span>
        <span class="php-keyword">return</span> [<span class="php-keyword">false</span>, <span class="php-string">"Rejected: extension .</span><span class="php-variable">$ext</span><span class="php-string"> is blocklisted."</span>];
    }
    <span class="php-keyword">return</span> [<span class="php-keyword">true</span>, <span class="php-string">"Accepted."</span>];   <span class="php-comment">// .phtml / .php5 / .pht slip through</span>
}
HTML;

require __DIR__ . '/render_level.php';
