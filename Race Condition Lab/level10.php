<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/level_defs.php';

$L = 10;
race_handle_reset($L);

$balance = 50 + (int)race_ledger_sum($L, 'balance');
$credits = (int)race_ledger_sum($L, 'credits');
$refunds = count(array_filter(race_ledger_rows($L, 'balance'), static fn($r) => (float)$r > 0));
$flag    = $balance > 200 ? race_flag($L) : '';

race_render($L, [
    'form' => race_launcher('api.php?level=10&op=buy', ['level' => 10, 'op' => 'buy'], 6, 'Buy credits, in parallel')
        . race_launcher('api.php?level=10&op=refund', ['level' => 10, 'op' => 'refund'], 6, 'Refund credits, in parallel')
        . '<p class="text-muted">Reload between the two bursts so you can watch the balance move, then repeat the
           cycle. A credit bought legitimately and refunded once returns exactly what it cost.</p>',
    'result' => race_state_block($L, [
            'balance'        => $balance,
            'credits held'   => $credits,
            'refunds issued' => $refunds,
            'target balance' => 'above 200',
        ], $balance > 200
            ? 'Balance is above the target. Every individual request was accepted by a check that was true when it ran.'
            : 'Started at 50. Buy at least one credit, then race the refunds, and repeat the cycle.')
        . race_log_block($L),
    'flag'     => $flag,
    'flag_msg' => 'Balance ' . $balance . ', starting from 50.',
]);
