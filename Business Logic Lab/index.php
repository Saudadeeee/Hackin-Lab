<?php
require_once __DIR__ . '/helpers.php';

lk_index_page(
    bizlab(),
    biz_levels(),
    'This is the lab for the finding a scanner will never report. Every level below is a working shop:
     real carts, real balances, real orders that persist between requests. None of them has an injection,
     a parser bug or a payload to discover. What each one has is a <em>rule</em> the developer wrote down
     slightly wrong - a range bounded on one side, a limit checked per request instead of per total, a
     ledger credited with the number next to the one it meant. You find those by reading the state machine
     and asking which transition nobody considered.',
    '<strong>How to work these levels:</strong> read the source panel first and draw the states and the money
     on paper. Every page prints the shop\'s actual arithmetic with your numbers in it, so when a total looks
     wrong you can point at the line where it went wrong. Levels are stateful - each one has a
     <strong>Reset this level</strong> button, and using it costs you nothing. Level 10 runs the same coupon
     engine you break in level 3 - in this shop nothing is ever fixed, it is only worked around.'
);
