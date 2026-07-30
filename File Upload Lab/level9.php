<?php
$levelId    = 9;
$levelTitle = 'Content Filter (<?php) Bypass';
$difficulty = 'Hard';

$scenario = <<<'HTML'
<p>Extensions are allowed here, but the uploader scans the file <strong>content</strong> and rejects
anything containing the string <code>&lt;?php</code>.</p>
<p>PHP has more than one way to open a code block. Use another one and read
<code>/var/secret/level9_flag.txt</code>.</p>
HTML;

$vulnNote = <<<'HTML'
<strong>Vulnerability:</strong>&nbsp; Blocking only the literal <code>&lt;?php</code> string misses other
executable openers. The short-echo tag <code>&lt;?=</code> is always enabled and runs code without the
blocked string. (<code>&lt;script language="php"&gt;</code> was removed in PHP 7, so <code>&lt;?=</code> is
the reliable bypass.) Content blocklists cannot reliably detect executable code.
HTML;

$sourceCode = <<<'HTML'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level9.php — scans file content for the "&lt;?php" string</span>
<span class="php-keyword">function</span> <span class="php-function">filter_level9</span>(<span class="php-keyword">array</span> <span class="php-variable">$u</span>): <span class="php-keyword">array</span> {
<span class="vuln-line">    <span class="php-keyword">if</span> (<span class="php-function">stripos</span>(<span class="php-variable">$u</span>[<span class="php-string">'content'</span>], <span class="php-string">'&lt;?php'</span>) !== <span class="php-keyword">false</span>) {   <span class="php-comment">// misses &lt;?=</span></span>
        <span class="php-keyword">return</span> [<span class="php-keyword">false</span>, <span class="php-string">"Rejected: content contains a &lt;?php tag."</span>];
    }
    <span class="php-keyword">return</span> [<span class="php-keyword">true</span>, <span class="php-string">"Accepted: no &lt;?php tag found."</span>];
}
<span class="php-comment">// shell.php with content &lt;?= readfile('...'); ?&gt; executes and passes.</span>
HTML;

require __DIR__ . '/render_level.php';
