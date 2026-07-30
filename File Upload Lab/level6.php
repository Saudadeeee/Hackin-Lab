<?php
$levelId    = 6;
$levelTitle = 'Case-Insensitive Extension Gap';
$difficulty = 'Medium';

$scenario = <<<'HTML'
<p>The blocklist is now thorough &mdash; it covers <code>php, phtml, php3, php4, php5, pht, phar</code>.
But the string comparison has one subtle flaw.</p>
<p>Slip a script past it and read <code>/var/secret/level6_flag.txt</code>.</p>
HTML;

$vulnNote = <<<'HTML'
<strong>Vulnerability:</strong>&nbsp; The extension is compared to the blocklist <em>without</em>
normalising case. The filesystem and Apache treat <code>.PhP</code> exactly like <code>.php</code>, yet the
mixed-case string never matches a lowercase blocklist entry. Always <code>strtolower()</code> before comparing.
HTML;

$sourceCode = <<<'HTML'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level6.php — comprehensive blocklist, but a case-sensitive compare</span>
<span class="php-keyword">function</span> <span class="php-function">filter_level6</span>(<span class="php-keyword">array</span> <span class="php-variable">$u</span>): <span class="php-keyword">array</span> {
    <span class="php-variable">$blocked</span> = [<span class="php-string">'php'</span>,<span class="php-string">'php3'</span>,<span class="php-string">'php4'</span>,<span class="php-string">'php5'</span>,<span class="php-string">'php7'</span>,<span class="php-string">'pht'</span>,<span class="php-string">'phtml'</span>,<span class="php-string">'phar'</span>];
    <span class="php-variable">$parts</span> = <span class="php-function">explode</span>(<span class="php-string">'.'</span>, <span class="php-variable">$u</span>[<span class="php-string">'name'</span>]);
<span class="vuln-line">    <span class="php-variable">$ext</span> = <span class="php-function">end</span>(<span class="php-variable">$parts</span>);                        <span class="php-comment">// BUG: never lowercased</span></span>
    <span class="php-keyword">if</span> (<span class="php-function">in_array</span>(<span class="php-variable">$ext</span>, <span class="php-variable">$blocked</span>, <span class="php-keyword">true</span>)) {          <span class="php-comment">// "PhP" != "php"</span>
        <span class="php-keyword">return</span> [<span class="php-keyword">false</span>, <span class="php-string">"Rejected: blocklisted extension."</span>];
    }
    <span class="php-keyword">return</span> [<span class="php-keyword">true</span>, <span class="php-string">"Accepted."</span>];
}
HTML;

require __DIR__ . '/render_level.php';
