<?php
require_once __DIR__ . '/helpers.php';

lk_index_page(
    cryptolab(),
    crypto_levels(),
    'AES is not broken. SHA-1 is not broken here either. Every level in this lab uses a sound primitive inside a
     construction that hands the attacker exactly the leverage they need - a repeated block, a reused nonce, a
     distinguishable error, an early-exit comparison. The point is to stop asking "is the algorithm strong" and
     start asking "what does this construction let me observe, and what can I change".',
    '<strong>Start here:</strong> the <a href="tools.php">Crypto Workbench</a> handles encoding, XOR, block
     splitting and the query loops, and prints its intermediate values so the method stays visible.
     <code>oracle.php</code> exposes the endpoints the scripted levels attack, so you can also write your own
     client in any language.'
);
