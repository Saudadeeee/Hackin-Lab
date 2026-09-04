<?php
require_once __DIR__ . '/helpers.php';

lk_index_page(
    racelab(),
    race_levels(),
    'Every endpoint in this lab is correct when one request runs at a time. Each level shows the source, the state
     it keeps, and a server-side log of how your requests actually interleaved - so a race that "did not reproduce"
     tells you something instead of nothing. The launcher fires the parallel requests for you and can warm the
     connections first, which is the difference between hitting a 150 ms window and a 25 ms one.',
    '<strong>Read the interleaving log.</strong> Two pids alternating between a read and its matching write is the
     signature of a race. Pids running one after another means something serialised your requests - level 6 exists
     entirely to teach you what.'
);
