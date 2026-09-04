<?php
require_once __DIR__ . '/helpers.php';

$L    = 4;
$meta = biz_levels()[$L];

shop_sid();
biz_handle_reset($L);

$catalog = shop_catalog($L);
$unit    = (float)$catalog['fastener']['price'];    // 0.336 - a real three-decimal trade price
$state   = shop_state($L);

$bought    = (int)$state['units_bought'];
$orderPaid = shop_cents($bought * $unit);           // 100.80, charged once, correctly

$flag     = '';
$result   = '';
$pipeline = [];

/* =========================================================================
 * The returns desk.
 *
 * A return is split into lines. Each line is priced, rounded to whole cents,
 * and added to the refund. The rounding happens inside the loop.
 * ===================================================================== */

if (($_POST['bl_action'] ?? '') === 'refund' || isset($_POST['per_line'])) {
    $perLine = (int)($_POST['per_line'] ?? 0);
    $lines   = (int)($_POST['lines'] ?? 1);   // a bare probe sends one line
    $units   = $perLine * $lines;
    $left    = $bought - (int)$state['units_returned'];

    $error = null;
    if ($perLine < 1 || $lines < 1) {
        $error = 'quantity per line and number of lines must both be at least 1';
    } elseif ($units > $left) {
        $error = 'you are trying to return ' . $units . ' units and only ' . $left . ' remain on the order';
    }

    // ── The refund calculation, exactly as written. ───────────────────────
    $exactPerLine   = $perLine * $unit;
    $roundedPerLine = round($exactPerLine, 2);       // <- rounding, per line, before the sum
    $refundBatch    = 0.0;
    for ($i = 0; $i < $lines; $i++) {
        $refundBatch += $roundedPerLine;
    }
    $refundBatch = round($refundBatch, 2);
    $exactBatch  = round($units * $unit, 2);

    $pipeline = [
        ['label' => 'unit price on the original order', 'value' => '$' . $unit,
         'note'  => 'Three decimals. Trade pricing routinely carries more precision than the currency does; the '
                  . 'currency only has to be exact at the moment money moves.'],
        ['label' => '$perLine * $unit  (exact value of one return line)',
         'value' => $perLine . ' x ' . $unit . ' = ' . rtrim(rtrim(number_format($exactPerLine, 6, '.', ''), '0'), '.'),
         'note'  => 'No rounding yet. This is what one line is genuinely worth.'],
        ['label' => 'round($perLine * $unit, 2)',
         'value' => number_format($roundedPerLine, 2, '.', ''),
         'note'  => ($roundedPerLine > $exactPerLine + 1e-9)
            ? 'Rounded <strong>up</strong> by ' . number_format($roundedPerLine - $exactPerLine, 4, '.', '')
              . ' dollars. Every line priced this way hands you that difference.'
            : (($roundedPerLine < $exactPerLine - 1e-9)
                ? 'Rounded <strong>down</strong> by ' . number_format($exactPerLine - $roundedPerLine, 4, '.', '')
                  . ' dollars. Lines priced this way cost you.'
                : 'Lands exactly on a cent boundary, so there is nothing to gain or lose on this line.')],
        ['label' => '$refund += (that value) for each of ' . $lines . ' lines',
         'value' => $lines . ' x ' . number_format($roundedPerLine, 2, '.', '') . ' = '
                  . number_format($refundBatch, 2, '.', '')],
        ['label' => 'what those ' . $units . ' units are actually worth',
         'value' => $units . ' x ' . $unit . ' = ' . number_format($exactBatch, 2, '.', ''),
         'note'  => 'The difference between this row and the one above it is the whole finding: '
                  . '<strong>' . number_format($refundBatch - $exactBatch, 2, '.', '') . '</strong> dollars, '
                  . 'created by where the <code>round()</code> call sits.',
         'verdict' => $refundBatch > $exactBatch ? 'pass' : null],
    ];

    if ($error !== null) {
        $result = biz_notice('error', 'Return rejected: ' . lk_esc($error) . '.');
    } else {
        $state['units_returned'] = (int)$state['units_returned'] + $units;
        $state['refunded']       = round((float)$state['refunded'] + $refundBatch, 2);
        $state['lines'][]        = ['per_line' => $perLine, 'lines' => $lines, 'units' => $units,
                                    'each' => $roundedPerLine, 'batch' => $refundBatch];
        shop_put($L, $state);
        $result = biz_notice('info', 'Refunded ' . shop_money($refundBatch) . ' for ' . $units
                . ' units across ' . $lines . ' line' . ($lines === 1 ? '' : 's') . '.');
    }
}

/* ── Flag: the refunded amount itself, not the shape of the request. ────── */
if (round((float)$state['refunded'], 2) >= 101.00) {
    $flag = biz_flag($L);
}

/* =========================================================================
 * Panels
 * ===================================================================== */

$lineRows = [];
foreach ($state['lines'] as $i => $b) {
    $lineRows[] = [
        '#' . ($i + 1),
        (int)$b['per_line'],
        (int)$b['lines'],
        (int)$b['units'],
        shop_money($b['each']),
        shop_money($b['batch']),
    ];
}

$returned = (int)$state['units_returned'];
$stateHtml = biz_kv([
    'Original order'   => $bought . ' x Micro-fastener M2 at $' . $unit . ' = <strong>'
                        . shop_money($orderPaid) . '</strong> (paid)',
    'Units returned'   => $returned . ' of ' . $bought . ' (' . ($bought - $returned) . ' left)',
    'Refunded so far'  => '<span class="biz-big">' . shop_money($state['refunded']) . '</span>',
    'Honest value of what you returned' => shop_money(round($returned * $unit, 2)),
    'Target'           => 'refunded total of ' . shop_money(101.00) . ' or more',
]) . biz_table(['Batch', 'Qty/line', 'Lines', 'Units', 'Refund per line', 'Batch refund'], $lineRows,
        'no returns filed yet');

ob_start(); ?>
<form method="post" action="">
    <input type="hidden" name="bl_action" value="refund">
    <div class="biz-grid">
        <div class="form-group">
            <label class="form-label">Quantity per return line</label>
            <input type="text" name="per_line" class="form-control" value="300" autocomplete="off">
        </div>
        <div class="form-group">
            <label class="form-label">Number of lines</label>
            <input type="text" name="lines" class="form-control" value="1" autocomplete="off">
        </div>
    </div>
    <button class="btn btn-primary" type="submit">File return</button>
</form>
<?= biz_reset_form() ?>
<?php
$form = biz_state_box('Return authorisation RA-2291', $stateHtml) . ob_get_clean();

$code = <<<'PHP'
// POST /returns/refund
// Trade prices carry three decimals; the currency carries two. Somewhere
// between the two, a decision has to be made about the third digit.
$unit   = $order['unit_price'];        // 0.336
$refund = 0.0;

foreach ($_POST['lines'] as $line) {
    $qty = (int)$line['qty'];
    if ($qty < 1 || $qty > $order['units_remaining']) {
        return error('invalid return quantity');
    }
    // Round to whole cents so each refund line prints cleanly on the
    // credit note, then add it to the total.
    $refund += round($qty * $unit, 2);
    $order['units_remaining'] -= $qty;
}

credit_customer($customer, $refund);
PHP;

$fixBad = <<<'PHP'
foreach ($lines as $line) {
    $refund += round($line['qty'] * $unit, 2);   // rounds, then sums
}
PHP;

$fixGood = <<<'PHP'
// Sum in the smallest indivisible unit - integer cents, or a decimal type -
// and round exactly once, at the point money actually moves.
$refundCents = 0;
foreach ($lines as $line) {
    // Prices are stored as integer tenths of a cent: 0.336 -> 3360.
    $refundCents += intdiv($line['qty'] * $unitTenthCents, 10);
}

// Whatever remains after the single division is a rounding decision. Make it
// explicitly, in favour of the party that did not choose the split, and log
// it - do not let it fall out of an expression by accident.
credit_customer($customer, $refundCents);

// And bound the outcome independently of the arithmetic: a refund can never
// exceed what was actually collected for the goods being returned.
assert($refundCents <= $order['amount_paid_cents']);
PHP;

lk_page([
    'lab'        => bizlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => biz_extra_head(),

    'code'       => $code,
    'vuln_lines' => [15],
    'annotation' => 'The refund is rounded to whole cents once per line and the rounded values are summed. Because
        the customer chooses how many lines the return is split into, the customer chooses how many times the
        rounding happens - and at a unit price of $0.336 each rounding hands back four tenths of a cent that were
        never paid.',

    'theory' => '<p>Money is not a real number, and floating point is not the interesting part of that sentence.
        The interesting part is that every arithmetic step either keeps a sub-unit fraction or discards it, and the
        <em>order</em> of the steps decides who ends up with it. <code>round(sum)</code> and <code>sum(round)</code>
        are different functions. They differ by an amount that is invisible per line and material per million
        lines.</p>
        <p>Real prices carry more precision than real currency. Per-unit trade rates, foreign-exchange conversions,
        percentage taxes, per-second billing, interest accrual - all of them produce values with a fractional cent
        in them, and all of them eventually meet a two-decimal field. The bug is not the fraction; the bug is
        rounding early, repeatedly, in a place where the number of repetitions is under someone else&rsquo;s
        control.</p>
        <p>The classic name for this is salami slicing, and the classic defence is the wrong one: people reach for
        a smaller epsilon or a decimal library and keep the same shape. Neither helps, because the shape is the
        problem. Sum in the smallest indivisible unit the currency has - integer cents - and round exactly once, at
        the boundary where money moves. Then decide, deliberately and in writing, who receives the last fraction.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Integer cents (or a fixed-point decimal type) for every intermediate value; a single rounding at
            the payment boundary; and an independent invariant next to the money - a refund can never exceed what
            was collected - so an arithmetic mistake cannot become a payout.',
    ],

    'scenario' => '<strong>Scenario:</strong> you bought 300 micro-fasteners at $0.336 each and paid
        <strong>' . shop_money(100.80) . '</strong>. You are returning them. The portal lets you split the return
        into as many lines as you like, and it will not let you return more units than you bought.
        <br><strong>Goal:</strong> be refunded <strong>' . shop_money(101.00) . '</strong> or more.',

    'model' => [
        'title' => 'round() moved one line up',
        'html'  => '<table class="lk-kv">
            <tr><td>what the code does</td><td><code>sum( round(qty x 0.336, 2) )</code> over your lines</td></tr>
            <tr><td>what it should do</td><td><code>round( sum(qty x 0.336), 2 )</code>, once, at the end</td></tr>
            <tr><td>you control</td><td>the quantity on each line, and how many lines there are</td></tr>
            <tr><td>you do not control</td><td>the unit price, or the 300-unit ceiling</td></tr>
        </table>
        <p>So work out, for small whole numbers <code>n</code>, how <code>round(n x 0.336, 2)</code> compares with
        the exact value <code>n x 0.336</code>:</p>
        <table class="data-table" style="margin-top:0.5rem">
            <thead><tr><th>n</th><th>exact</th><th>rounded</th><th>difference per line</th></tr></thead>
            <tbody>
                <tr><td>1</td><td>0.336</td><td>0.34</td><td>+0.004</td></tr>
                <tr><td>2</td><td>0.672</td><td>0.67</td><td>-0.002</td></tr>
                <tr><td>3</td><td>1.008</td><td>1.01</td><td>+0.002</td></tr>
                <tr><td>4</td><td>1.344</td><td>1.34</td><td>-0.004</td></tr>
            </tbody>
        </table>
        <p>Now the level is arithmetic: pick the row with the largest positive difference, multiply it by how many
        lines 300 units allows at that quantity, and add the result to ' . shop_money(100.80) . '.</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    // Stateful levels can be reset after a solve, so the inline submit box
    // keeps accepting this level's flag even once the winning state is gone.
    'expected_flag' => biz_flag($L),
    'flag_msg' => 'You have been refunded more than the goods cost, one rounding at a time.',
    'why'      => '<p>The trace prints the exact value of a line and the rounded value of the same line next to
        each other, and then prints the batch total against what those units are actually worth. Nothing in that
        sequence is a trick: the difference is created entirely by the position of one <code>round()</code>
        call.</p>
        <p>The flag was awarded for the refunded amount in your account. That number is the state; the request that
        produced it is incidental, and several different splits reach the same place.</p>
        <p>Two habits come out of this level. First, when reviewing money code, find every <code>round</code>,
        <code>floor</code>, <code>ceil</code> and cast, and ask how many times each one can run per transaction and
        who decides that count. Second, ask what the smallest unit of the currency is and whether any intermediate
        value is allowed to be smaller than it.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'per_line',
        'method' => 'POST',
        'action' => 'level4.php',
        'items'  => [
            ['q' => 'What does one line of 2 units round to?',
             'payload' => '2',
             'learn'   => 'Sends a single two-unit line. Read the third trace row: it prints the exact value, the rounded value, and the direction. That row is the measurement you need for every other quantity.'],
            ['q' => 'And a line of 3?',
             'payload' => '3',
             'learn'   => 'A different remainder, and it rounds the other way. Two data points are enough to see that the direction depends on the quantity rather than on anything about the request.'],
            ['q' => 'Does the whole return in one line lose the effect entirely?',
             'payload' => '300',
             'learn'   => 'The honest baseline: one line, one rounding, ' . shop_money(100.80) . '. Reset the level afterwards - the 300-unit ceiling is shared across every return you file.'],
        ],
    ],
    'hints' => biz_hints($L),
]);
