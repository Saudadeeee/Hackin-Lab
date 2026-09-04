<?php
require_once __DIR__ . '/helpers.php';

$L    = 9;
$meta = biz_levels()[$L];

shop_sid();
biz_handle_reset($L);

$state = shop_state($L);

$flag     = '';
$result   = '';
$pipeline = [];

/* The two rates. They were set by two different teams, a year apart. */
const BIZ_POINTS_PER_DOLLAR_OUT = 50;    // redemption: 50 points buys $1.00 of credit
const BIZ_POINTS_PER_DOLLAR_IN  = 100;   // earning:    $1.00 spent earns 100 points
const BIZ_TARGET_CREDIT         = 50.00;

$action = (string)($_POST['bl_action'] ?? '');

/* =========================================================================
 * Operation 1: redeem points for store credit.
 * ===================================================================== */
if ($action === 'redeem' || isset($_POST['points'])) {
    $points = (int)($_POST['points'] ?? 0);
    $have   = (int)$state['points'];

    $err = null;
    if ($points < BIZ_POINTS_PER_DOLLAR_OUT) {
        $err = 'minimum redemption is ' . BIZ_POINTS_PER_DOLLAR_OUT . ' points';
    } elseif ($points > $have) {
        $err = 'you have ' . number_format($have) . ' points';
    }

    $credit = shop_cents($points / BIZ_POINTS_PER_DOLLAR_OUT);

    $pipeline = [
        ['label' => 'points redeemed', 'value' => number_format($points) . ' of ' . number_format($have)],
        ['label' => '$credit = $points / ' . BIZ_POINTS_PER_DOLLAR_OUT,
         'value' => number_format($points) . ' / ' . BIZ_POINTS_PER_DOLLAR_OUT . ' = ' . shop_money($credit),
         'note'  => 'The redemption rate. One point is worth <strong>$0.02</strong> of credit on the way out.',
         'verdict' => $err === null ? 'pass' : 'block'],
    ];

    if ($err !== null) {
        $result = biz_notice('error', 'Redemption declined: ' . lk_esc($err) . '.');
    } else {
        $state['points'] = $have - $points;
        $state['credit'] = shop_cents((float)$state['credit'] + $credit);
        $state['log'][]  = ['op' => 'redeem', 'detail' => number_format($points) . ' pts -> ' . shop_money($credit),
                            'points' => $state['points'], 'credit' => $state['credit']];
        shop_put($L, $state);
        $result = biz_notice('info', 'Redeemed ' . number_format($points) . ' points for '
                . shop_money($credit) . ' of store credit.');
    }
}

/* =========================================================================
 * Operation 2: spend credit in the store. The loyalty engine awards points
 * on the amount spent, and it does not care where the money came from.
 * ===================================================================== */
if ($action === 'spend' || isset($_POST['spend'])) {
    $spend = round((float)($_POST['spend'] ?? 0), 2);
    $have  = (float)$state['credit'];

    $err = null;
    if ($spend < 0.01) {
        $err = 'spend at least ' . shop_money(0.01);
    } elseif ($spend > $have) {
        $err = 'you have ' . shop_money($have) . ' of credit';
    }

    $earned = (int)floor($spend * BIZ_POINTS_PER_DOLLAR_IN);

    $pipeline = [
        ['label' => 'credit spent', 'value' => shop_money($spend) . ' of ' . shop_money($have)],
        ['label' => '$points = floor($spend * ' . BIZ_POINTS_PER_DOLLAR_IN . ')',
         'value' => shop_money($spend) . ' x ' . BIZ_POINTS_PER_DOLLAR_IN . ' = ' . number_format($earned)
                  . ' points',
         'note'  => 'The earning rate. One point costs <strong>$0.01</strong> of spend on the way in. The engine '
                  . 'awards points on the transaction amount and never asks whether the money was cash or credit '
                  . 'that came from points in the first place.',
         'verdict' => $err === null ? 'pass' : 'block'],
    ];

    if ($err !== null) {
        $result = biz_notice('error', 'Purchase declined: ' . lk_esc($err) . '.');
    } else {
        $state['credit'] = shop_cents($have - $spend);
        $state['points'] = (int)$state['points'] + $earned;
        $state['log'][]  = ['op' => 'spend', 'detail' => shop_money($spend) . ' -> ' . number_format($earned) . ' pts',
                            'points' => $state['points'], 'credit' => $state['credit']];
        shop_put($L, $state);
        $result = biz_notice('info', 'Spent ' . shop_money($spend) . ' and earned '
                . number_format($earned) . ' loyalty points.');
    }
}

/* ── Flag: the credit balance actually held. ───────────────────────────── */
if ((float)$state['credit'] >= BIZ_TARGET_CREDIT) {
    $flag = biz_flag($L);
}

/* =========================================================================
 * Panels
 * ===================================================================== */

$logRows = [];
foreach (array_slice($state['log'], -12) as $i => $e) {
    $logRows[] = ['<code>' . lk_esc($e['op']) . '</code>', lk_esc($e['detail']),
                  number_format((int)$e['points']), shop_money($e['credit'])];
}

$stateHtml = biz_kv([
    'Loyalty points'  => '<span class="biz-big">' . number_format((int)$state['points']) . '</span>',
    'Store credit'    => '<span class="biz-big">' . shop_money($state['credit']) . '</span>',
    'Redemption rate' => BIZ_POINTS_PER_DOLLAR_OUT . ' points = ' . shop_money(1.00)
                       . ' of credit &nbsp;<span class="text-muted">($0.02 per point)</span>',
    'Earning rate'    => shop_money(1.00) . ' spent = ' . BIZ_POINTS_PER_DOLLAR_IN
                       . ' points &nbsp;<span class="text-muted">($0.01 per point)</span>',
    'Target'          => 'hold ' . shop_money(BIZ_TARGET_CREDIT) . ' or more of store credit',
]) . '<p class="lk-hintline" style="margin-top:0.7rem">Ledger (most recent 12)</p>'
   . biz_table(['Op', 'Detail', 'Points after', 'Credit after'], $logRows, 'nothing done yet');

ob_start(); ?>
<div class="lk-split">
    <form method="post" action="">
        <input type="hidden" name="bl_action" value="redeem">
        <div class="form-group">
            <label class="form-label">Redeem points for credit</label>
            <input type="text" name="points" class="form-control"
                   value="<?= (int)$state['points'] ?>" autocomplete="off">
        </div>
        <button class="btn btn-primary" type="submit">Redeem</button>
    </form>
    <form method="post" action="">
        <input type="hidden" name="bl_action" value="spend">
        <div class="form-group">
            <label class="form-label">Spend credit in the store</label>
            <input type="text" name="spend" class="form-control"
                   value="<?= number_format((float)$state['credit'], 2, '.', '') ?>" autocomplete="off">
        </div>
        <button class="btn btn-primary" type="submit">Spend</button>
    </form>
</div>
<?= biz_reset_form() ?>
<?php
$form = biz_state_box('Loyalty account', $stateHtml) . ob_get_clean();

$code = <<<'PHP'
// loyalty/redeem.php   - written when the scheme launched
// "Points are worth two cents each when you cash them in."
const POINTS_PER_DOLLAR = 50;

$points = (int)$_POST['points'];
if ($points < POINTS_PER_DOLLAR || $points > $customer['points']) {
    return error('invalid redemption');
}
$customer['points'] -= $points;
$customer['credit'] += $points / POINTS_PER_DOLLAR;      // $0.02 a point

// loyalty/earn.php     - added a year later by the growth team
// "Give people 100 points per dollar, it sounds more generous."
const POINTS_PER_DOLLAR_SPENT = 100;

function on_purchase(array $customer, float $amount): void
{
    // The engine is called from the payment hook with the transaction
    // amount. It has no idea how the transaction was funded.
    $customer['points'] += (int)floor($amount * POINTS_PER_DOLLAR_SPENT);
}
PHP;

$fixBad = <<<'PHP'
const POINTS_PER_DOLLAR       = 50;    // out: $0.02 a point
const POINTS_PER_DOLLAR_SPENT = 100;   // in:  $0.01 a point
PHP;

$fixGood = <<<'PHP'
// Two independent repairs; a scheme this size wants both.
//
// 1. Points are earned on money that entered the business, not on money the
//    business already owed you. The earning hook needs the funding source.
function on_purchase(Payment $p, Customer $c): void
{
    $eligible = $p->amount - $p->fundedFromStoreCredit;
    $c->points += (int)floor($eligible * POINTS_PER_DOLLAR_SPENT);
}

// 2. The redemption rate must never exceed the earning rate, and that is an
//    invariant worth asserting rather than a comment worth writing.
//        earn:   1 dollar  -> 100 points
//        redeem: 50 points -> 1 dollar,  so 100 points -> $2.00
//    A round trip returns $2.00 for $1.00. Any scheme where
//        (1 / POINTS_PER_DOLLAR) * POINTS_PER_DOLLAR_SPENT > 1
//    is a money printer, so refuse to boot on it:
if (POINTS_PER_DOLLAR_SPENT > POINTS_PER_DOLLAR) {
    throw new ConfigurationError('loyalty round trip is net positive');
}
PHP;

lk_page([
    'lab'        => bizlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => biz_extra_head(),

    'code'       => $code,
    'vuln_lines' => [3, 14, 20],
    'annotation' => 'Points leave the scheme at two cents each and come back at one cent each. Each rate was set
        by a team that was only looking at its own direction, and neither file mentions the other. Because store
        credit can be spent, and spending earns points, the two rates form a cycle - and a cycle whose product is
        greater than one is a machine.',

    'theory' => '<p>Whenever a system lets a value be converted from A to B and back from B to A, the two rates
        stop being independent numbers. They become a loop, and the only question that matters is what one full
        circuit does to the quantity you started with. If the product of the rates is exactly one, the loop is
        closed and nothing is created. If it is less than one, the loop leaks and nobody complains. If it is
        greater than one, the loop is an amplifier, and its output is bounded only by how many times someone is
        willing to go round.</p>
        <p>The reason this is hard to spot in a code review is that neither rate is wrong on its own page.
        Redeeming at two cents is a normal, defensible loyalty rate. Earning a hundred points per dollar is a
        normal, defensible marketing decision. The defect does not exist in either file; it exists in the
        composition, and no reviewer read both files at once because they were written a year apart by different
        teams.</p>
        <p>The same reasoning applies well beyond loyalty points: currency pairs on an exchange, referral credit
        that itself earns referral credit, cashback on a payment method that is topped up with cashback, staking
        rewards, discount tiers computed from discounted spend. When you meet two conversion rates, draw the cycle
        and multiply. This is arithmetic, not fuzzing - and it is the only reliable way to find this class, because
        every single request in the exploit is a legitimate one.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Break the cycle by excluding credit-funded spend from earning, and independently assert that a
            round trip cannot be net positive. The second check is cheap and it catches the version of this bug
            that arrives two years later when marketing changes one constant.',
    ],

    'scenario' => '<strong>Scenario:</strong> a loyalty scheme with two operations. Redeem points for store
        credit, or spend store credit in the shop. You start with <strong>100 points</strong> and
        ' . shop_money(0.00) . ' of credit. Every request you will send is a legitimate one that the shop offers on
        its own front page.
        <br><strong>Goal:</strong> hold <strong>' . shop_money(BIZ_TARGET_CREDIT) . '</strong> or more of store
        credit.',

    'model' => [
        'title' => 'Do the arithmetic before you click',
        'html'  => '<table class="lk-kv">
            <tr><td>out of the scheme</td><td>' . BIZ_POINTS_PER_DOLLAR_OUT . ' points -> ' . shop_money(1.00)
                . ' &nbsp;<strong>= $0.02 per point</strong></td></tr>
            <tr><td>into the scheme</td><td>' . shop_money(1.00) . ' spent -> ' . BIZ_POINTS_PER_DOLLAR_IN
                . ' points &nbsp;<strong>= $0.01 per point</strong></td></tr>
            <tr><td>one full round trip</td><td><code>P</code> points -> <code>P/50</code> dollars -> <code>(P/50) x 100</code> = <strong>2P</strong> points</td></tr>
        </table>
        <p>The loop doubles. That is not an approximation and it does not depend on rounding: <code>P/50 x 100</code>
        is exactly <code>2P</code> for any <code>P</code> that is a multiple of 50, and every balance you reach
        along the way is a multiple of 50.</p>
        <p>So after <code>n</code> complete loops you hold <code>100 x 2^n</code> points, which redeem to
        <code>$2.00 x 2^n</code>:</p>
        <table class="data-table" style="margin-top:0.5rem">
            <thead><tr><th>loops</th><th>points</th><th>if you redeem and stop</th></tr></thead>
            <tbody>
                <tr><td>0</td><td>100</td><td>' . shop_money(2.00) . '</td></tr>
                <tr><td>1</td><td>200</td><td>' . shop_money(4.00) . '</td></tr>
                <tr><td>2</td><td>400</td><td>' . shop_money(8.00) . '</td></tr>
                <tr><td>3</td><td>800</td><td>' . shop_money(16.00) . '</td></tr>
                <tr><td>4</td><td>1,600</td><td>' . shop_money(32.00) . '</td></tr>
                <tr><td>5</td><td>3,200</td><td>' . shop_money(64.00) . '</td></tr>
            </tbody>
        </table>
        <p>Read the last column and pick the row that clears ' . shop_money(BIZ_TARGET_CREDIT) . '. A loop is one
        redeem followed by one spend; the final redeem is the one you do not spend.</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    // Stateful levels can be reset after a solve, so the inline submit box
    // keeps accepting this level's flag even once the winning state is gone.
    'expected_flag' => biz_flag($L),
    'flag_msg' => 'Every request was a legitimate operation. The scheme itself is the defect.',
    'why'      => '<p>Nothing in the ledger is an abuse of an individual endpoint. Each redemption redeemed points
        you held; each purchase spent credit you held; each award followed the published earning rate. There is no
        request in the log that a support agent would query.</p>
        <p>The flag was awarded for the credit balance, because the balance is the only place the defect is
        visible. That is the defining feature of this class of bug: no single event is anomalous, and the
        <em>sequence</em> is impossible. Detection has to live at the account level - a points balance growing
        without a corresponding cash payment - because no request-level rule will ever fire.</p>
        <p>The reasoning that got you here is worth naming, because it transfers. You found two conversion rates
        between the same pair of quantities, wrote both as a price per unit, multiplied them around the cycle, and
        got a number greater than one. Then you counted the loops. No payload, no guessing - the exploit was
        finished on paper before the first request.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'points',
        'method' => 'POST',
        'action' => 'level9.php',
        'items'  => [
            ['q' => 'What is one point actually worth on the way out?',
             'payload' => '50',
             'learn'   => 'The minimum redemption. Trace step 2 prints the division, which pins the outbound rate exactly rather than trusting the marketing copy.'],
            ['q' => 'Is the redemption bounded by the points you hold?',
             'payload' => '100000',
             'learn'   => 'Far more than you have. A rejection tells you the balance is the ceiling, so growth has to come from the earning side rather than from a bad bound here.'],
            ['q' => 'Is there a minimum, and does it round in anyone\'s favour?',
             'payload' => '49',
             'learn'   => 'One below the floor. Worth knowing whether small redemptions are refused or silently rounded - the answer changes whether the loop is exact or leaky.'],
        ],
    ],
    'hints' => biz_hints($L),
]);
