<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/level_defs.php';

$L = 3;
race_handle_reset($L);

$withdrawn = (int)race_ledger_sum($L, 'withdrawals');
$balance   = 100 - $withdrawn;
$flag      = $withdrawn >= 200 ? race_flag($L) : '';

race_render($L, [
    'form'   => race_launcher('api.php?level=3', ['level' => 3], 4, 'Withdraw 100, in parallel'),
    'result' => race_state_block($L, [
            'balance'   => $balance,
            'withdrawn' => $withdrawn,
        ], $balance < 0
            ? 'The account is overdrawn. Every one of those withdrawals passed a real balance check.'
            : 'Balance is still non-negative. Send the withdrawals together rather than one after another.')
        . race_log_block($L),
    'flag'     => $flag,
    'flag_msg' => 'Withdrew ' . $withdrawn . ' from an account holding 100.',
]);
