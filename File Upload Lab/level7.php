<?php
$levelId    = 7;
$levelTitle = '.htaccess Handler Injection';
$difficulty = 'Hard';

$scenario = <<<'HTML'
<p>Every PHP-family extension is blocked, so you cannot upload a script directly. But the upload
directory honours <code>.htaccess</code> overrides, and the filter does not block dotfiles.</p>
<p>Upload an <code>.htaccess</code> that maps a benign extension to PHP, then upload
<code>shell.jpg</code> to execute code and read <code>/var/secret/level7_flag.txt</code>.</p>
HTML;

$vulnNote = <<<'HTML'
<strong>Vulnerability:</strong>&nbsp; Blocking script extensions is not enough when the upload directory
allows <code>.htaccess</code>. An uploaded <code>.htaccess</code> can re-map any extension (e.g. <code>.jpg</code>)
to the PHP handler, turning a "harmless" image into executable code. Never let uploads land where
<code>AllowOverride</code> is enabled.
HTML;

$sourceCode = <<<'HTML'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level7.php — blocks scripts, but permits .htaccess into an AllowOverride dir</span>
<span class="php-keyword">function</span> <span class="php-function">filter_level7</span>(<span class="php-keyword">array</span> <span class="php-variable">$u</span>): <span class="php-keyword">array</span> {
    <span class="php-variable">$blocked</span> = [<span class="php-string">'php'</span>,<span class="php-string">'php3'</span>,<span class="php-string">'php4'</span>,<span class="php-string">'php5'</span>,<span class="php-string">'php7'</span>,<span class="php-string">'pht'</span>,<span class="php-string">'phtml'</span>,<span class="php-string">'phar'</span>];
    <span class="php-variable">$ext</span> = <span class="php-function">strtolower</span>(<span class="php-function">pathinfo</span>(<span class="php-variable">$u</span>[<span class="php-string">'name'</span>], <span class="php-keyword">PATHINFO_EXTENSION</span>));
    <span class="php-keyword">if</span> (<span class="php-function">in_array</span>(<span class="php-variable">$ext</span>, <span class="php-variable">$blocked</span>, <span class="php-keyword">true</span>)) {
        <span class="php-keyword">return</span> [<span class="php-keyword">false</span>, <span class="php-string">"Rejected: script extension blocklisted."</span>];
    }
<span class="vuln-line">    <span class="php-keyword">return</span> [<span class="php-keyword">true</span>, <span class="php-string">"Accepted."</span>];   <span class="php-comment">// .htaccess passes -> remap .jpg to PHP</span></span>
}
HTML;

require __DIR__ . '/render_level.php';
