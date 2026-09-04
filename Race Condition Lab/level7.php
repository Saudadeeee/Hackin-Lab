<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/level_defs.php';

$L = 7;
race_handle_reset($L);

$s    = race_read($L, ['status' => 'pending', 'refunded' => false, 'shipped' => false]);
$flag = (!empty($s['refunded']) && !empty($s['shipped'])) ? race_flag($L) : '';

race_render($L, [
    'form' => race_launcher('api.php?level=7&op=ship', ['level' => 7, 'op' => 'ship'], 2, 'Ship the order')
        . race_launcher('api.php?level=7&op=cancel', ['level' => 7, 'op' => 'cancel'], 2, 'Cancel the order')
        . '<p class="text-muted">Send one of each at the same moment. Firing many copies of a single operation will
           not reach the state you want.</p>',
    'result' => race_state_block($L, [
            'order status' => $s['status'],
            'refunded'     => !empty($s['refunded']) ? 'true' : 'false',
            'shipped'      => !empty($s['shipped']) ? 'true' : 'false',
        ], (!empty($s['refunded']) && !empty($s['shipped']))
            ? 'Both side effects happened. No legal sequence of transitions reaches this state.'
            : 'Reset and try again if one of them rejected - both need to read "pending".')
        . race_log_block($L),
    'flag'     => $flag,
    'flag_msg' => 'The money went back and the parcel went out.',
]);
