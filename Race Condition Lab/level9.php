<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/level_defs.php';

$L = 9;
race_handle_reset($L);

$spent = 50 * race_ledger_count($L, 'purchases');
$s     = race_read($L, ['version' => 1]);
$flag  = $spent > 100 ? race_flag($L) : '';

race_render($L, [
    'form'   => race_launcher('api.php?level=9', ['level' => 9], 6, 'Purchase for 50, in parallel'),
    'result' => race_state_block($L, [
            'balance' => 100 - $spent,
            'version' => $s['version'],
            'spent'   => $spent,
        ], $spent > 100
            ? 'Spent ' . $spent . ' from an account that held 100, with the version check passing every time.'
            : 'Spent ' . $spent . '. Requests that hit the conflict check are rejected honestly, so send enough that several land inside the same version.')
        . race_log_block($L),
    'flag'     => $flag,
    'flag_msg' => 'The version matched, and it protected nothing.',
]);
