<?php
require_once __DIR__ . '/helpers.php';

lk_index_page(
    arlab(),
    ar_levels(),
    'Password recovery exists to hand an account back to someone who has lost access to it. That makes it a
     second, quieter authentication system, usually written later, usually reviewed less, and usually able to
     overrule everything the first one enforces. These ten levels take one recovery flow apart: who the form
     admits exists, where the token comes from, what the token is allowed to name, how long it lives, how many
     guesses the code survives, and what a session means once the login is over. Every level runs the real flow
     against real rows, and the flag is awarded for the state you reach, never for the string you send.',
    '<strong>Your account:</strong> <code>guest@hackinlab.internal</code> / <code>guest123</code>. <strong>The
     target:</strong> <code>admin@hackinlab.internal</code>, whose mailbox you cannot read &mdash; that
     restriction is the premise of every level. <a href="mailbox.php?level=1">Your mailbox</a> shows the mail the
     application sends you; <a href="collector.php">collector.php</a> is a host you control. Each level has its
     own accounts, tokens, mail and sessions, and a <em>Reset this level</em> button that rebuilds them.'
);
