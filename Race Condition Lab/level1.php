<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/level_defs.php';

$L = 1;
race_handle_reset($L);

$s    = race_read($L, ['counter' => 0]);
$acks = race_ledger_count($L, 'acks');
$lost = $acks - (int)$s['counter'];

$flag = $lost > 0 ? race_flag($L) : '';

race_render($L, [
    'form'   => race_launcher('api.php?level=1', ['level' => 1], 10, 'Increment the counter, in parallel'),
    'result' => race_state_block($L, [
            'counter (read-modify-write)' => $s['counter'],
            'acknowledgements (append-only)' => $acks,
            'updates lost' => $lost,
        ], $lost > 0
            ? 'Every acknowledged request believed it succeeded. ' . $lost . ' of those increments no longer exist.'
            : 'The two numbers agree, so no update has been lost yet. Send a larger burst.')
        . race_log_block($L),
    'flag'     => $flag,
    'flag_msg' => $lost . ' increment' . ($lost === 1 ? '' : 's') . ' destroyed with no error anywhere.',
]);
