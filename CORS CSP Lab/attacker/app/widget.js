/**
 * Served from the second origin (127.0.0.1 instead of localhost, or the other
 * way round). render.php never links to this file. It only ever runs when an
 * injected <base href> rewrote the relative URL of the page own widget script,
 * and the nonce on that element travelled with it.
 */
hlab.win('attacker/app/widget.js, reached through the injected <base>');
