<?php
/**
 * Business Logic Lab · the shop
 * ---------------------------------------------------------------------------
 * Everything in this file is ordinary, boring e-commerce plumbing: a catalogue,
 * a per-learner state file, and money formatting. The *rules* that are wrong
 * live in the individual level pages, because that is where a business-logic
 * bug actually lives — not in a library, not in a parser, but in the sequence
 * of steps somebody wrote on a whiteboard.
 *
 * State model
 * -----------
 * Each browser gets a random session id in the `bizlogic_sid` cookie. State is
 * a single JSON document per session, namespaced by level:
 *
 *     state/<sid>.json  =>  { "1": {...}, "2": {...}, ... }
 *
 * Business-logic levels are stateful by nature, so every level page exposes a
 * "Reset this level" button that drops its namespace back to the defaults.
 */

/* =========================================================================
 * Session identity
 * ===================================================================== */

/** Stable per-browser id. Created on first use; must run before any output. */
function shop_sid(): string
{
    static $sid = null;
    if ($sid !== null) {
        return $sid;
    }
    $raw = (string)($_COOKIE['bizlogic_sid'] ?? '');
    if (preg_match('/^[a-f0-9]{32}$/', $raw)) {
        return $sid = $raw;
    }
    $sid = bin2hex(random_bytes(16));
    if (!headers_sent()) {
        setcookie('bizlogic_sid', $sid, time() + 86400 * 30, '/');
    }
    $_COOKIE['bizlogic_sid'] = $sid;   // usable within this same request
    return $sid;
}

/* =========================================================================
 * State storage
 * ===================================================================== */

/**
 * Where the JSON documents live. `state/` next to the code is preferred so the
 * files are easy to inspect; if that directory is not writable (a read-only
 * bind mount, a different web user) we fall back to the system temp directory,
 * so a permissions problem never presents itself as a broken level.
 */
function shop_state_dir(): string
{
    static $dir = null;
    if ($dir !== null) {
        return $dir;
    }
    $preferred = __DIR__ . '/state';
    if (!is_dir($preferred)) {
        @mkdir($preferred, 0777, true);
    }
    if (is_dir($preferred) && is_writable($preferred)) {
        return $dir = $preferred;
    }
    $fallback = sys_get_temp_dir() . '/bizlogic_state';
    if (!is_dir($fallback)) {
        @mkdir($fallback, 0777, true);
    }
    return $dir = $fallback;
}

function shop_state_file(): string
{
    return shop_state_dir() . '/' . shop_sid() . '.json';
}

/** Whole document for this session. */
function shop_load_all(): array
{
    $f = shop_state_file();
    if (!is_file($f)) {
        return [];
    }
    $decoded = json_decode((string)@file_get_contents($f), true);
    return is_array($decoded) ? $decoded : [];
}

function shop_save_all(array $doc): void
{
    @file_put_contents(shop_state_file(), json_encode($doc, JSON_PRETTY_PRINT), LOCK_EX);
}

/** State for one level, with any missing keys filled in from the defaults. */
function shop_state(int $level): array
{
    $all = shop_load_all();
    $cur = is_array($all[(string)$level] ?? null) ? $all[(string)$level] : [];
    return $cur + shop_defaults($level);
}

function shop_put(int $level, array $state): void
{
    $all = shop_load_all();
    $all[(string)$level] = $state;
    shop_save_all($all);
}

function shop_reset(int $level): void
{
    $all = shop_load_all();
    unset($all[(string)$level]);
    shop_save_all($all);
}

/* =========================================================================
 * Money
 * ===================================================================== */

/** Display helper. Negative amounts read as -$12.34, which matters a lot here. */
function shop_money($amount): string
{
    $a = (float)$amount;
    return ($a < 0 ? '-$' : '$') . number_format(abs($a), 2, '.', ',');
}

/** Round to whole cents. Used wherever the shop is behaving correctly. */
function shop_cents(float $amount): float
{
    return round($amount, 2);
}

/* =========================================================================
 * Catalogue
 * ===================================================================== */

/**
 * Per-level catalogue. Keeping them separate means a level can price an item
 * however its story needs without disturbing its neighbours.
 *
 * @return array<string, array{name:string, price:float, note?:string, gate?:string}>
 */
function shop_catalog(int $level): array
{
    switch ($level) {
        case 1:
            return [
                'mug'    => ['name' => 'Lab Mug',            'price' => 9.50],
                'hoodie' => ['name' => 'Hackin Hoodie',      'price' => 45.00],
                'laptop' => ['name' => 'Refurbished Laptop', 'price' => 899.99],
            ];
        case 2:
            return [
                'cable'       => ['name' => 'USB-C Cable',                 'price' => 12.00],
                'keyboard'    => ['name' => 'Mechanical Keyboard',         'price' => 89.00],
                'ent-support' => ['name' => 'Enterprise Support Contract', 'price' => 9999.00,
                                  'note' => 'restricted - sales-assisted purchase only'],
            ];
        case 3:
            return [
                'headphones' => ['name' => 'Noise-cancelling Headphones', 'price' => 180.00],
                'case'       => ['name' => 'Hard Carry Case',             'price' => 30.00],
            ];
        case 4:
            return [
                'fastener' => ['name' => 'Micro-fastener M2 (each)', 'price' => 0.336],
            ];
        case 5:
            return [
                'giftcard' => ['name' => 'Digital Gift Card', 'price' => 10.00],
                'sticker'  => ['name' => 'Sticker Pack',      'price' => 4.00],
            ];
        case 6:
            return [
                'deskmat' => ['name' => 'Desk Mat',      'price' => 19.00],
                'desk'    => ['name' => 'Standing Desk', 'price' => 649.00],
            ];
        case 7:
            return [
                'headset' => ['name' => 'Pro Headset',   'price' => 249.00],
                'stand'   => ['name' => 'Monitor Stand', 'price' => 79.00],
            ];
        case 8:
            return [
                'monitor' => ['name' => '27-inch Monitor', 'price' => 329.00],
                'cable'   => ['name' => 'USB-C Cable',     'price' => 12.50],
            ];
        case 10:
            return [
                'rack'     => ['name' => 'Server Rack Unit',        'price' => 1000.00],
                'keyboard' => ['name' => 'Mechanical Keyboard',     'price' => 89.00],
                'founders' => ['name' => 'Founders Edition Hoodie', 'price' => 19.00,
                               'gate' => 'platinum',
                               'note' => 'platinum members only'],
            ];
        default:
            return [];
    }
}

/* =========================================================================
 * Coupons (levels 3 and 10 share the same unfixed coupon engine)
 * ===================================================================== */

/**
 * Every code is marked single use and first-order only. Read the terms and
 * they look airtight; read the code that enforces them and they are not.
 *
 * @return array<string, array{label:string, type:string, value:float}>
 */
function shop_coupons(): array
{
    return [
        'FIRST10'   => ['label' => '10% off your first order', 'type' => 'pct', 'value' => 0.10],
        'WELCOME15' => ['label' => '15% off your first order', 'type' => 'pct', 'value' => 0.15],
        'NEWBIE20'  => ['label' => '20% off your first order', 'type' => 'pct', 'value' => 0.20],
        'SPRING25'  => ['label' => '25% off your first order', 'type' => 'pct', 'value' => 0.25],
        'LOYAL30'   => ['label' => '30% off your first order', 'type' => 'pct', 'value' => 0.30],
    ];
}

/* =========================================================================
 * Per-level starting state
 * ===================================================================== */

function shop_defaults(int $level): array
{
    switch ($level) {
        case 1:
            return ['balance' => 25.00, 'cart' => [], 'orders' => []];

        case 2:
            return ['balance' => 25.00, 'orders' => []];

        case 3:
            // A cart the shop built, not the learner: 180.00 + 2 x 30.00.
            return [
                'cart'       => [
                    ['item' => 'headphones', 'qty' => 1],
                    ['item' => 'case',       'qty' => 2],
                ],
                'used_codes' => [],
                'orders'     => [],
            ];

        case 4:
            // 300 fasteners at 0.336 each were bought and paid for: 100.80.
            return [
                'units_bought'   => 300,
                'units_returned' => 0,
                'refunded'       => 0.00,
                'lines'          => [],
            ];

        case 5:
            return ['balance' => 25.00, 'orders' => []];

        case 6:
            return ['balance' => 25.00, 'order' => null, 'history' => []];

        case 7:
            return ['balance' => 25.00, 'orders' => [], 'last' => null];

        case 8:
            // An order that is already paid for. Refunds are issued against it.
            return [
                'balance' => 0.00,
                'order'   => [
                    'id'    => 'ORD-88412',
                    'total' => 354.00,
                    'paid'  => 354.00,
                    'lines' => [
                        ['item' => '27-inch Monitor', 'qty' => 1, 'unit' => 329.00, 'total' => 329.00],
                        ['item' => 'USB-C Cable',     'qty' => 2, 'unit' => 12.50,  'total' => 25.00],
                    ],
                ],
                'refunds' => [],
            ];

        case 9:
            return ['points' => 100, 'credit' => 0.00, 'log' => []];

        case 10:
            return [
                'balance'        => 25.00,
                'lifetime_spend' => 0.00,
                'used_codes'     => [],
                'orders'         => [],
                'owned'          => [],
            ];
    }
    return [];
}

/* =========================================================================
 * Tier ladder (level 10)
 * ===================================================================== */

function shop_tiers(): array
{
    return [
        ['tier' => 'bronze',   'min' => 0.00],
        ['tier' => 'silver',   'min' => 500.00],
        ['tier' => 'gold',     'min' => 2000.00],
        ['tier' => 'platinum', 'min' => 10000.00],
    ];
}

function shop_tier_for(float $lifetimeSpend): string
{
    $tier = 'bronze';
    foreach (shop_tiers() as $row) {
        if ($lifetimeSpend >= $row['min']) {
            $tier = $row['tier'];
        }
    }
    return $tier;
}

/* =========================================================================
 * The 32-bit warehouse field (levels 5 and 10 both talk to this service)
 * ===================================================================== */

/**
 * The fulfilment service speaks a fixed-width binary protocol whose quantity
 * field is a signed 32-bit integer. `pack('l', ...)` truncates to 32 bits and
 * `unpack('l', ...)` reinterprets those four bytes as signed - exactly what the
 * Java service on the other end of the wire does with the same four bytes.
 *
 * Nothing here is a trick. This is the ordinary behaviour of an int32 field,
 * isolated into one function so a level can print it in a trace.
 */
function shop_warehouse_qty(int $qty): int
{
    return unpack('l', pack('l', $qty))[1];
}
