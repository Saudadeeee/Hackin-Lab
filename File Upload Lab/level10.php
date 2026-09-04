<?php
$levelId    = 10;
$levelTitle = 'Multi-Layer WAF Bypass';
$difficulty = 'Expert';

$scenario = <<<'HTML'
<p>The finale stacks four defences on every upload: a last-extension blocklist, a required
<code>image/png</code> Content-Type, an image magic-byte check, and a <code>&lt;?php</code> content scan.</p>
<p>Exactly one payload satisfies all four at once. Build it and read
<code>/var/secret/level10_flag.txt</code>.</p>
HTML;

$vulnNote = <<<'HTML'
<strong>Vulnerability:</strong>&nbsp; Each layer is individually bypassable, and one payload defeats them
together: a <strong>double extension</strong> (<code>shell.php.jpg</code>, last ext <code>jpg</code>) +
a forged <code>image/png</code> MIME + a <code>GIF89a</code> magic-byte prefix + a <code>&lt;?=</code>
short-echo tag (dodging the <code>&lt;?php</code> scan). Stacked blocklists are still blocklists.
HTML;

$sourceCode = <<<'HTML'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level10.php — four stacked filters; one payload survives all of them</span>
<span class="php-keyword">function</span> <span class="php-function">filter_level10</span>(<span class="php-keyword">array</span> <span class="php-variable">$u</span>): <span class="php-keyword">array</span> {
    <span class="php-variable">$blocked</span> = [<span class="php-string">'php'</span>,<span class="php-string">'php3'</span>,<span class="php-string">'php4'</span>,<span class="php-string">'php5'</span>,<span class="php-string">'php7'</span>,<span class="php-string">'pht'</span>,<span class="php-string">'phtml'</span>,<span class="php-string">'phar'</span>];
    <span class="php-variable">$ext</span> = <span class="php-function">strtolower</span>(<span class="php-function">pathinfo</span>(<span class="php-variable">$u</span>[<span class="php-string">'name'</span>], <span class="php-keyword">PATHINFO_EXTENSION</span>));
    <span class="php-keyword">if</span> (<span class="php-function">in_array</span>(<span class="php-variable">$ext</span>, <span class="php-variable">$blocked</span>, <span class="php-keyword">true</span>))            <span class="php-keyword">return</span> [<span class="php-keyword">false</span>, <span class="php-string">"Layer 1: extension"</span>];
    <span class="php-keyword">if</span> (<span class="php-variable">$u</span>[<span class="php-string">'mime'</span>] !== <span class="php-string">'image/png'</span>)                <span class="php-keyword">return</span> [<span class="php-keyword">false</span>, <span class="php-string">"Layer 2: MIME"</span>];
    <span class="php-keyword">if</span> (!<span class="php-function">has_image_magic</span>(<span class="php-variable">$u</span>[<span class="php-string">'content'</span>]))            <span class="php-keyword">return</span> [<span class="php-keyword">false</span>, <span class="php-string">"Layer 3: magic"</span>];  <span class="php-comment">// GIF/PNG/JPEG sigs</span>
<span class="vuln-line">    <span class="php-keyword">if</span> (<span class="php-function">stripos</span>(<span class="php-variable">$u</span>[<span class="php-string">'content'</span>], <span class="php-string">'&lt;?php'</span>) !== <span class="php-keyword">false</span>)  <span class="php-keyword">return</span> [<span class="php-keyword">false</span>, <span class="php-string">"Layer 4: content"</span>];</span>
    <span class="php-keyword">return</span> [<span class="php-keyword">true</span>, <span class="php-string">"Accepted: survived all four layers."</span>];
}
<span class="php-comment">// Win: shell.php.jpg + image/png + "GIF89a;&lt;?= ... ?&gt;"</span>
HTML;

require __DIR__ . '/render_level.php';
