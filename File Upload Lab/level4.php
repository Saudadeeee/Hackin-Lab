<?php
$levelId    = 4;
$levelTitle = 'Magic Byte Validation Bypass';
$difficulty = 'Medium';

$scenario = <<<'HTML'
<p>Smarter now: the uploader reads the first bytes of the file to confirm it is a real image
before accepting it under <code>uploads/level4/</code>.</p>
<p>Craft a polyglot that looks like an image at the start but still runs as PHP, then read
<code>/var/secret/level4_flag.txt</code>.</p>
HTML;

$vulnNote = <<<'HTML'
<strong>Vulnerability:</strong>&nbsp; The magic-byte check only inspects the <em>start</em> of the file.
A file that begins with <code>GIF89a</code> passes the check yet still contains and executes PHP that
follows it. The extension is unrestricted, so a <code>.php</code> polyglot is served as code.
HTML;

$sourceCode = <<<'HTML'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level4.php — validates image magic bytes at the start of the file</span>
<span class="php-keyword">function</span> <span class="php-function">filter_level4</span>(<span class="php-keyword">array</span> <span class="php-variable">$u</span>): <span class="php-keyword">array</span> {
    <span class="php-variable">$head</span> = <span class="php-function">substr</span>(<span class="php-variable">$u</span>[<span class="php-string">'content'</span>], <span class="php-string">0</span>, <span class="php-string">6</span>);
<span class="vuln-line">    <span class="php-keyword">if</span> (<span class="php-variable">$head</span> !== <span class="php-string">'GIF89a'</span> &amp;&amp; <span class="php-variable">$head</span> !== <span class="php-string">'GIF87a'</span> <span class="php-comment">/* + PNG/JPEG sigs */</span>) {</span>
        <span class="php-keyword">return</span> [<span class="php-keyword">false</span>, <span class="php-string">"Rejected: not a valid image (magic bytes)."</span>];
    }
    <span class="php-keyword">return</span> [<span class="php-keyword">true</span>, <span class="php-string">"Accepted: image magic bytes detected."</span>];
}
<span class="php-comment">// Content after the header still executes: GIF89a;&lt;?php ... ?&gt; in shell.php</span>
HTML;

require __DIR__ . '/render_level.php';
