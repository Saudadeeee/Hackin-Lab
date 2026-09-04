<?php
/**
 * GraphQL Lab · data store, seed data and the ten level schemas
 * ---------------------------------------------------------------------------
 * Everything the levels serve comes out of a real SQLite database, built on
 * first run. Resolvers query it the way an ordinary service would, which is
 * what makes the authorisation bugs in this lab honest: the row exists, the
 * query returns it, and the only question is whether anything checked first.
 *
 * Each level gets its own schema function. They overlap on purpose - the User
 * type of level 3 and level 4 differ by one resolver, and comparing the two is
 * the point of level 4.
 */

require_once __DIR__ . '/graphql.php';

/* =========================================================================
 * Database
 * ===================================================================== */

function gq_db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $dir = __DIR__ . '/data';
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
    }
    $file = $dir . '/graphql.sqlite';
    if (!is_dir($dir) || (!is_writable($dir) && !is_file($file))) {
        $file = sys_get_temp_dir() . '/graphql_lab.sqlite';       // read-only bind mount fallback
    }
    $fresh = !is_file($file) || filesize($file) === 0;
    $pdo   = new PDO('sqlite:' . $file);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_SILENT);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    if ($fresh) {
        gq_build($pdo);
    }
    // The CLI self-test runs as root and the web server as www-data, and both
    // write to this file. Without the widened mode, whichever process creates
    // it first silently locks the other out of every UPDATE.
    @chmod($file, 0666);
    return $pdo;
}

function gq_build(PDO $db): void
{
    $db->exec('CREATE TABLE users (
        id INTEGER PRIMARY KEY, username TEXT, name TEXT, email TEXT, role TEXT,
        ssn TEXT, api_token TEXT, private_note TEXT)');
    $db->exec('CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, category TEXT)');
    $db->exec('CREATE TABLE memos (id INTEGER PRIMARY KEY, title TEXT, author TEXT, content TEXT)');
    $db->exec('CREATE TABLE staff_notes (id INTEGER PRIMARY KEY, area TEXT, on_call_pin TEXT)');
    $db->exec('CREATE TABLE coupons (code TEXT PRIMARY KEY, reward TEXT)');
    $db->exec('CREATE TABLE audit_log (id INTEGER PRIMARY KEY, actor TEXT, entry TEXT)');
    $db->exec('CREATE TABLE employees (id INTEGER PRIMARY KEY, name TEXT, title TEXT,
        manager_id INTEGER, safe_id INTEGER)');
    $db->exec('CREATE TABLE safes (id INTEGER PRIMARY KEY, label TEXT, combination TEXT)');
    $db->exec('CREATE TABLE documents (id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT,
        body TEXT, secret_note TEXT)');
    $db->exec('CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)');
    $db->exec('CREATE TABLE rate_hits (id INTEGER PRIMARY KEY, ip TEXT, level INTEGER, ts INTEGER)');

    $ins = $db->prepare('INSERT INTO users VALUES (?,?,?,?,?,?,?,?)');
    $ins->execute([1, 'root', 'Dana Root', 'dana@shipyard.example', 'admin',
        '541-22-9087', gq_secret(4), 'root recovery phrase kept in the safe']);
    $ins->execute([2, 'guest', 'Guest Analyst', 'guest@shipyard.example', 'user',
        '000-00-0000', 'sk_test_guest_readonly', 'nothing interesting in here']);
    $ins->execute([3, 'amercer', 'Alice Mercer', 'alice@shipyard.example', 'user',
        '332-88-1104', 'sk_live_alice_2f81', 'personal ' . gq_secret(3)]);
    $ins->execute([4, 'operator', 'Ops Operator', 'ops@shipyard.example', 'analyst',
        '110-45-7781', 'sk_live_ops_5510', 'on-call rota is in the wiki']);
    $ins->execute([5, 'mreed', 'Morgan Reed', 'morgan@shipyard.example', 'support',
        '773-01-4429', 'sk_live_reed_88a1', 'support macros need a rewrite']);

    $ins = $db->prepare('INSERT INTO products VALUES (?,?,?,?)');
    $ins->execute([1, 'Anchor Chain 12mm', 189.0, 'rigging']);
    $ins->execute([2, 'Deck Cleat, bronze', 41.5, 'hardware']);
    $ins->execute([3, 'Bilge Pump 800GPH', 96.0, 'pumps']);

    $ins = $db->prepare('INSERT INTO memos VALUES (?,?,?,?)');
    $ins->execute([1, 'Office move', 'facilities', 'Third floor is closed for cabling on the 14th.']);
    $ins->execute([2, 'Holiday cover', 'people', 'Support rota published, no changes to on-call.']);
    $ins->execute([3, 'Q3 launch', 'exec',
        'Embargo holds until the 30th. Press kit codeword: ' . gq_secret(1)]);

    $ins = $db->prepare('INSERT INTO staff_notes VALUES (?,?,?)');
    $ins->execute([1, 'reception', 'PIN-1000-LOBBY']);
    $ins->execute([2, 'zurich-rack', gq_secret(2)]);

    $db->prepare('INSERT INTO coupons VALUES (?,?)')->execute(['7C', gq_secret(5)]);

    $ins = $db->prepare('INSERT INTO audit_log VALUES (?,?,?)');
    $ins->execute([1, 'root', 'rotated the storefront TLS certificate']);
    $ins->execute([2, 'root', 'issued payroll export key: ' . gq_secret(7)]);
    $ins->execute([3, 'operator', 'restarted the queue worker']);

    $db->prepare('INSERT INTO safes VALUES (?,?,?)')->execute([1, 'Executive safe, 4th floor', gq_secret(8)]);
    $ins = $db->prepare('INSERT INTO employees VALUES (?,?,?,?,?)');
    $ins->execute([1, 'Guest Analyst', 'Analyst', 2, null]);
    $ins->execute([2, 'Priya Raman', 'Team Lead', 3, null]);
    $ins->execute([3, 'Ken Osei', 'Director of Operations', 4, 1]);
    $ins->execute([4, 'Dana Root', 'Chief Executive', null, 1]);

    $ins = $db->prepare('INSERT INTO documents VALUES (?,?,?,?,?)');
    $ins->execute([1, 2, 'Onboarding checklist', 'Badge, laptop, VPN profile.', 'none']);
    $ins->execute([2, 2, 'Dock survey notes', 'Pier 4 needs new fenders.', 'none']);
    $ins->execute([3, 1, 'Hull revision D', 'Restricted drawing set.', 'blueprint ' . gq_secret(9)]);

    $db->prepare('INSERT INTO settings VALUES (?,?)')->execute(['vault_key', gq_secret(10)]);
    $db->prepare('INSERT INTO settings VALUES (?,?)')->execute(['region', 'eu-central-1']);
}

/** Undo everything the mutation levels changed, so a level can be replayed. */
function gq_reset_state(): void
{
    $db = gq_db();
    $db->prepare('UPDATE users SET role = ? WHERE id = ?')->execute(['support', 5]);
    $db->prepare('UPDATE users SET role = ? WHERE id = ?')->execute(['analyst', 4]);
    $db->exec('DELETE FROM rate_hits');
}

/* --- tiny query helpers used by the resolvers ---------------------------- */

function gq_row(string $sql, array $params = []): ?array
{
    $st = gq_db()->prepare($sql);
    if (!$st || !$st->execute($params)) {
        return null;
    }
    $row = $st->fetch();
    return $row === false ? null : $row;
}

function gq_rows(string $sql, array $params = []): array
{
    $st = gq_db()->prepare($sql);
    if (!$st || !$st->execute($params)) {
        return [];
    }
    return $st->fetchAll();
}

function gq_user(int $id): ?array
{
    return gq_row('SELECT * FROM users WHERE id = ?', [$id]);
}

/* =========================================================================
 * Secrets
 * ---------------------------------------------------------------------
 * The value a level's flag is awarded for. It is stored in the database and
 * only reaches the learner if the server actually hands it over, which is why
 * no level can be solved by writing a query that merely looks right.
 * ===================================================================== */

function gq_secret(int $level): string
{
    $s = [
        1  => 'SPRINGLOADED-7742',
        2  => 'PIN-4471-ZURICH',
        3  => 'savings-8842-1190',
        4  => 'sk_live_9f3c1d7a44b0e5',
        5  => 'VOUCHER-8811-OPEN',
        6  => 'role-escalated-by-mutation',
        7  => 'PX-4417-QQ',
        8  => '19-42-07-63',
        9  => 'bp-hash-7c1f9ae2',
        10 => 'vault-key-a91f-0c33',
    ];
    return $s[$level] ?? '';
}

/* =========================================================================
 * Shared type fragments
 * ===================================================================== */

/** The public part of a user, used wherever authorisation is not the lesson. */
function gq_type_product(): array
{
    return ['kind' => 'OBJECT', 'desc' => 'A catalogue item.', 'fields' => [
        'id'       => ['type' => 'Int!'],
        'name'     => ['type' => 'String!'],
        'price'    => ['type' => 'Float'],
        'category' => ['type' => 'String'],
    ]];
}

function gq_field_products(): array
{
    return ['type' => '[Product]', 'desc' => 'Everything in the public catalogue.',
            'resolve' => static fn() => gq_rows('SELECT * FROM products ORDER BY id')];
}

/* =========================================================================
 * Level schemas
 * ===================================================================== */

/** Level 1 - introspection is on and the schema has more in it than the UI uses. */
function gq_schema_l1(): array
{
    return [
        'query' => 'Query',
        'types' => [
            'Query' => ['kind' => 'OBJECT', 'desc' => 'Storefront read API.', 'fields' => [
                'me'       => ['type' => 'User', 'desc' => 'The signed-in shopper.',
                               'resolve' => static fn() => gq_user(2)],
                'products' => gq_field_products(),
                'product'  => ['type' => 'Product', 'args' => ['id' => ['type' => 'Int!']],
                               'resolve' => static fn($r, $a) => gq_row('SELECT * FROM products WHERE id = ?',
                                   [(int)($a['id'] ?? 0)])],
                'internalMemo' => [
                    'type' => 'Memo',
                    'desc' => 'Internal comms. Not referenced by the storefront bundle.',
                    'args' => ['id' => ['type' => 'Int!']],
                    'resolve' => static fn($r, $a) => gq_row('SELECT * FROM memos WHERE id = ?',
                        [(int)($a['id'] ?? 0)]),
                ],
            ]],
            'User' => ['kind' => 'OBJECT', 'fields' => [
                'id'       => ['type' => 'Int!'],
                'username' => ['type' => 'String!'],
                'name'     => ['type' => 'String'],
                'role'     => ['type' => 'String'],
            ]],
            'Product' => gq_type_product(),
            'Memo'    => ['kind' => 'OBJECT', 'desc' => 'An internal memo.', 'fields' => [
                'id'      => ['type' => 'Int!'],
                'title'   => ['type' => 'String'],
                'author'  => ['type' => 'String'],
                'content' => ['type' => 'String'],
            ]],
        ],
    ];
}

/** Level 2 - introspection is off, but unknown-field errors still suggest. */
function gq_schema_l2(): array
{
    return [
        'query' => 'Query',
        'types' => [
            'Query' => ['kind' => 'OBJECT', 'fields' => [
                'me'       => ['type' => 'User', 'resolve' => static fn() => gq_user(2)],
                'products' => gq_field_products(),
                'orders'   => ['type' => '[String]', 'resolve' => static fn() => ['no orders yet']],
                'staffNotes' => ['type' => '[StaffNote]', 'desc' => 'Operations notes. Staff console only.',
                                 'resolve' => static fn() => gq_rows('SELECT * FROM staff_notes ORDER BY id')],
            ]],
            'User' => ['kind' => 'OBJECT', 'fields' => [
                'id'          => ['type' => 'Int!'],
                'username'    => ['type' => 'String!'],
                'name'        => ['type' => 'String'],
                'privateNote' => ['type' => 'String',
                                  'resolve' => static fn($u) => $u['private_note'] ?? null],
            ]],
            'Product'   => gq_type_product(),
            'StaffNote' => ['kind' => 'OBJECT', 'fields' => [
                'id'        => ['type' => 'Int!'],
                'area'      => ['type' => 'String'],
                'onCallPin' => ['type' => 'String', 'resolve' => static fn($n) => $n['on_call_pin'] ?? null],
            ]],
        ],
    ];
}

/** Level 3 - user(id:) never compares the id to the session. GraphQL's IDOR. */
function gq_schema_l3(int $sessionUserId): array
{
    return [
        'query' => 'Query',
        'types' => [
            'Query' => ['kind' => 'OBJECT', 'fields' => [
                'me'   => ['type' => 'User', 'resolve' => static fn() => gq_user($sessionUserId)],
                'user' => [
                    'type' => 'User',
                    'desc' => 'Look up an account by id.',
                    'args' => ['id' => ['type' => 'Int!']],
                    'resolve' => static function ($root, $args, $ctx) use ($sessionUserId) {
                        $id  = (int)($args['id'] ?? 0);
                        $row = gq_user($id);
                        // No comparison with $sessionUserId happens anywhere below.
                        if (isset($ctx['trace'])) {
                            $ctx['trace']->add(
                                'resolver Query.user(id: ' . $id . ')',
                                'SELECT * FROM users WHERE id = ' . $id . '  ->  '
                                . ($row ? 'row for "' . $row['username'] . '"' : 'no row'),
                                'Session is user #' . $sessionUserId . '. The resolver never reads the session, so
                                 the two numbers are never compared.',
                                $row ? 'pass' : 'block'
                            );
                        }
                        return $row;
                    },
                ],
                'products' => gq_field_products(),
            ]],
            'User' => ['kind' => 'OBJECT', 'fields' => [
                'id'          => ['type' => 'Int!'],
                'username'    => ['type' => 'String!'],
                'name'        => ['type' => 'String'],
                'email'       => ['type' => 'String'],
                'role'        => ['type' => 'String'],
                'privateNote' => ['type' => 'String', 'desc' => 'Only the account owner should read this.',
                                  'resolve' => static fn($u) => $u['private_note'] ?? null],
            ]],
            'Product' => gq_type_product(),
        ],
    ];
}

/**
 * Level 4 - object-level authorisation was fixed, field-level was not.
 * Query.user marks the row it returns as authorised or not; the field
 * resolvers that were written at the same time honour the mark, and the one
 * that was bolted on later for the mobile app does not.
 */
function gq_schema_l4(int $sessionUserId): array
{
    $guarded = static function (string $column) {
        return static function ($u) use ($column) {
            if (empty($u['_authorised'])) {
                throw new GqlError('Not authorised to read User.' . $column . ' for another account.');
            }
            return $u[$column] ?? null;
        };
    };

    return [
        'query' => 'Query',
        'types' => [
            'Query' => ['kind' => 'OBJECT', 'fields' => [
                'me'   => ['type' => 'User', 'resolve' => static function () use ($sessionUserId) {
                    $u                = gq_user($sessionUserId);
                    $u['_authorised'] = true;
                    return $u;
                }],
                'user' => [
                    'type' => 'User',
                    'args' => ['id' => ['type' => 'Int!']],
                    'resolve' => static function ($root, $args, $ctx) use ($sessionUserId) {
                        $id  = (int)($args['id'] ?? 0);
                        $row = gq_user($id);
                        if (!$row) {
                            return null;
                        }
                        $row['_authorised'] = ($id === $sessionUserId);
                        if (isset($ctx['trace'])) {
                            $ctx['trace']->add(
                                'resolver Query.user(id: ' . $id . ')',
                                '_authorised = ' . ($row['_authorised'] ? 'true' : 'false'),
                                'The object-level decision is made once, here, and stored on the row. Every field
                                 resolver is then trusted to consult it.',
                                $row['_authorised'] ? 'pass' : 'block'
                            );
                        }
                        return $row;
                    },
                ],
            ]],
            'User' => ['kind' => 'OBJECT', 'fields' => [
                'id'          => ['type' => 'Int!'],
                'username'    => ['type' => 'String!'],
                'name'        => ['type' => 'String'],
                'role'        => ['type' => 'String'],
                'email'       => ['type' => 'String', 'resolve' => $guarded('email')],
                'ssn'         => ['type' => 'String', 'resolve' => $guarded('ssn')],
                'privateNote' => ['type' => 'String', 'resolve' => $guarded('private_note')],
                // Added in the mobile-app sprint. Reads the token straight from
                // the table by id and never looks at _authorised.
                'apiToken'    => ['type' => 'String', 'desc' => 'Personal API token.',
                    'resolve' => static function ($u, $a, $ctx) {
                        $row = gq_row('SELECT api_token FROM users WHERE id = ?', [(int)$u['id']]);
                        if (isset($ctx['trace'])) {
                            $ctx['trace']->add(
                                'resolver User.apiToken',
                                'SELECT api_token FROM users WHERE id = ' . (int)$u['id'],
                                'This resolver does its own fetch and never reads <code>_authorised</code>. The
                                 parent decision is not part of its code path at all.',
                                'pass'
                            );
                        }
                        return $row['api_token'] ?? null;
                    }],
            ]],
        ],
    ];
}

/** Level 5 - one operation per alias, and the limiter counts requests. */
function gq_schema_l5(): array
{
    return [
        'query' => 'Query',
        'types' => [
            'Query' => ['kind' => 'OBJECT', 'fields' => [
                'me'     => ['type' => 'User', 'resolve' => static fn() => gq_user(2)],
                'redeem' => [
                    'type' => 'RedeemResult',
                    'desc' => 'Redeem a two-character launch voucher code.',
                    'args' => ['code' => ['type' => 'String!']],
                    'resolve' => static function ($root, $args) {
                        $code = strtoupper(trim((string)($args['code'] ?? '')));
                        $row  = gq_row('SELECT reward FROM coupons WHERE code = ?', [$code]);
                        return ['code' => $code, 'ok' => (bool)$row,
                                'reward' => $row['reward'] ?? null];
                    },
                ],
            ]],
            'User' => ['kind' => 'OBJECT', 'fields' => [
                'id'       => ['type' => 'Int!'],
                'username' => ['type' => 'String!'],
            ]],
            'RedeemResult' => ['kind' => 'OBJECT', 'fields' => [
                'code'   => ['type' => 'String'],
                'ok'     => ['type' => 'Boolean'],
                'reward' => ['type' => 'String'],
            ]],
        ],
    ];
}

/** Level 6 - the mutation itself has no authorisation code at all. */
function gq_schema_l6(int $sessionUserId): array
{
    return [
        'query'    => 'Query',
        'mutation' => 'Mutation',
        'types'    => [
            'Query' => ['kind' => 'OBJECT', 'fields' => [
                'me'    => ['type' => 'User', 'resolve' => static fn() => gq_user($sessionUserId)],
                'users' => ['type' => '[User]',
                            'resolve' => static fn() => gq_rows('SELECT * FROM users ORDER BY id')],
            ]],
            'Mutation' => ['kind' => 'OBJECT', 'fields' => [
                'updateDisplayName' => [
                    'type' => 'User',
                    'args' => ['name' => ['type' => 'String!']],
                    'resolve' => static function ($r, $a) use ($sessionUserId) {
                        gq_db()->prepare('UPDATE users SET name = ? WHERE id = ?')
                               ->execute([(string)$a['name'], $sessionUserId]);
                        return gq_user($sessionUserId);
                    },
                ],
                'promoteUser' => [
                    'type' => 'User',
                    'desc' => 'Privileged. Registered in the operation table as "PromoteUser".',
                    'args' => ['id' => ['type' => 'Int!'], 'role' => ['type' => 'String!']],
                    'resolve' => static function ($r, $a, $ctx) {
                        $id   = (int)($a['id'] ?? 0);
                        $role = (string)($a['role'] ?? '');
                        gq_db()->prepare('UPDATE users SET role = ? WHERE id = ?')->execute([$role, $id]);
                        if (isset($ctx['trace'])) {
                            $ctx['trace']->add(
                                'resolver Mutation.promoteUser',
                                'UPDATE users SET role = "' . $role . '" WHERE id = ' . $id,
                                'No role check inside the resolver. The middleware was the only control, and the
                                 middleware never ran.',
                                'pass'
                            );
                        }
                        return gq_user($id);
                    },
                ],
            ]],
            'User' => ['kind' => 'OBJECT', 'fields' => [
                'id'       => ['type' => 'Int!'],
                'username' => ['type' => 'String!'],
                'name'     => ['type' => 'String'],
                'role'     => ['type' => 'String'],
            ]],
        ],
    ];
}

/** Level 7 - the audit log has no resolver-level check; the batch guard was it. */
function gq_schema_l7(): array
{
    return [
        'query' => 'Query',
        'types' => [
            'Query' => ['kind' => 'OBJECT', 'fields' => [
                'me'       => ['type' => 'User', 'resolve' => static fn() => gq_user(2)],
                'products' => gq_field_products(),
                'auditLog' => [
                    'type' => '[AuditEntry]',
                    'desc' => 'Administrative audit trail.',
                    'resolve' => static function ($r, $a, $ctx) {
                        if (isset($ctx['trace'])) {
                            $ctx['trace']->add('resolver Query.auditLog',
                                'SELECT * FROM audit_log ORDER BY id',
                                'The resolver has no authorisation code. Whatever reached it is served.', 'pass');
                        }
                        return gq_rows('SELECT * FROM audit_log ORDER BY id');
                    },
                ],
            ]],
            'User' => ['kind' => 'OBJECT', 'fields' => [
                'id'       => ['type' => 'Int!'],
                'username' => ['type' => 'String!'],
                'role'     => ['type' => 'String'],
            ]],
            'Product'    => gq_type_product(),
            'AuditEntry' => ['kind' => 'OBJECT', 'fields' => [
                'id'    => ['type' => 'Int!'],
                'actor' => ['type' => 'String'],
                'entry' => ['type' => 'String'],
            ]],
        ],
    ];
}

/** Level 8 - a recursive org chart, with the interesting data four hops up. */
function gq_schema_l8(): array
{
    return [
        'query' => 'Query',
        'types' => [
            'Query' => ['kind' => 'OBJECT', 'fields' => [
                'me' => ['type' => 'Employee', 'desc' => 'Your own employee record.',
                         'resolve' => static fn() => gq_row('SELECT * FROM employees WHERE id = 1')],
            ]],
            'Employee' => ['kind' => 'OBJECT', 'fields' => [
                'id'      => ['type' => 'Int!'],
                'name'    => ['type' => 'String'],
                'title'   => ['type' => 'String'],
                'manager' => ['type' => 'Employee', 'desc' => 'The person this employee reports to.',
                    'resolve' => static fn($e) => $e['manager_id']
                        ? gq_row('SELECT * FROM employees WHERE id = ?', [(int)$e['manager_id']]) : null],
                'safe'    => ['type' => 'Safe', 'desc' => 'Safe this employee is a keyholder for.',
                    'resolve' => static fn($e) => $e['safe_id']
                        ? gq_row('SELECT * FROM safes WHERE id = ?', [(int)$e['safe_id']]) : null],
            ]],
            'Safe' => ['kind' => 'OBJECT', 'fields' => [
                'label'       => ['type' => 'String'],
                'combination' => ['type' => 'String'],
            ]],
        ],
    ];
}

/** Level 9 - the filter argument is typed String and pasted into SQL. */
function gq_schema_l9(): array
{
    return [
        'query' => 'Query',
        'types' => [
            'Query' => ['kind' => 'OBJECT', 'fields' => [
                'me' => ['type' => 'User', 'resolve' => static fn() => gq_user(2)],
                'searchDocuments' => [
                    'type' => '[Document]',
                    'desc' => 'Search your documents by title.',
                    'args' => ['filter' => ['type' => 'String!']],
                    'resolve' => static function ($r, $a, $ctx) {
                        $filter = (string)($a['filter'] ?? '');
                        // The argument was validated as a String. Nothing looked inside it.
                        $sql = "SELECT id, title, body FROM documents WHERE title LIKE '%" . $filter . "%'";
                        $st  = gq_db()->query($sql);
                        $err = $st ? null : (gq_db()->errorInfo()[2] ?? 'query failed');
                        if (isset($ctx['trace'])) {
                            $ctx['trace']->add('resolver Query.searchDocuments -> SQL', $sql,
                                $err !== null ? 'SQLite error: <code>' . htmlspecialchars($err, ENT_QUOTES) . '</code>'
                                    : 'The quotes around the filter belong to the developer. Everything between
                                       them belongs to whoever sent the argument.',
                                $err !== null ? 'block' : 'pass');
                        }
                        if (!$st) {
                            throw new GqlError('searchDocuments failed: ' . $err);
                        }
                        return $st->fetchAll();
                    },
                ],
            ]],
            'User' => ['kind' => 'OBJECT', 'fields' => [
                'id'       => ['type' => 'Int!'],
                'username' => ['type' => 'String!'],
            ]],
            'Document' => ['kind' => 'OBJECT', 'fields' => [
                'id'    => ['type' => 'Int!'],
                'title' => ['type' => 'String'],
                'body'  => ['type' => 'String'],
            ]],
        ],
    ];
}

/** Level 10 - the chain: discover the mutation, dodge the guard, read the vault. */
function gq_schema_l10(int $sessionUserId): array
{
    return [
        'query'    => 'Query',
        'mutation' => 'Mutation',
        'types'    => [
            'Query' => ['kind' => 'OBJECT', 'fields' => [
                'me' => ['type' => 'User', 'resolve' => static fn() => gq_user($sessionUserId)],
                'adminSettings' => [
                    'type' => 'AdminSettings',
                    'desc' => 'Requires the admin role at request time.',
                    'resolve' => static function ($r, $a, $ctx) use ($sessionUserId) {
                        $role = (string)(gq_user($sessionUserId)['role'] ?? '');
                        if (isset($ctx['trace'])) {
                            $ctx['trace']->add('resolver Query.adminSettings',
                                'role of session user #' . $sessionUserId . ' read live from the database: ' . $role,
                                'This is a real check, and it is the one control the chain has to satisfy rather
                                 than dodge.',
                                $role === 'admin' ? 'pass' : 'block');
                        }
                        if ($role !== 'admin') {
                            throw new GqlError('Forbidden: adminSettings requires role "admin", you have "'
                                . $role . '".');
                        }
                        $rows = [];
                        foreach (gq_rows('SELECT key, value FROM settings') as $s) {
                            $rows[$s['key']] = $s['value'];
                        }
                        return $rows;
                    },
                ],
            ]],
            'Mutation' => ['kind' => 'OBJECT', 'fields' => [
                'grantRole' => [
                    'type' => 'User',
                    'desc' => 'Privileged. Registered in the operation table as "GrantRole".',
                    'args' => ['userId' => ['type' => 'Int!'], 'role' => ['type' => 'String!']],
                    'resolve' => static function ($r, $a, $ctx) {
                        $id   = (int)($a['userId'] ?? 0);
                        $role = (string)($a['role'] ?? '');
                        gq_db()->prepare('UPDATE users SET role = ? WHERE id = ?')->execute([$role, $id]);
                        if (isset($ctx['trace'])) {
                            $ctx['trace']->add('resolver Mutation.grantRole',
                                'UPDATE users SET role = "' . $role . '" WHERE id = ' . $id,
                                'The write is real and it persists. The next request reads the new role.', 'pass');
                        }
                        return gq_user($id);
                    },
                ],
            ]],
            'User' => ['kind' => 'OBJECT', 'fields' => [
                'id'       => ['type' => 'Int!'],
                'username' => ['type' => 'String!'],
                'name'     => ['type' => 'String'],
                'role'     => ['type' => 'String'],
            ]],
            'AdminSettings' => ['kind' => 'OBJECT', 'fields' => [
                'region'   => ['type' => 'String'],
                'vaultKey' => ['type' => 'String', 'resolve' => static fn($s) => $s['vault_key'] ?? null],
            ]],
        ],
    ];
}

/* =========================================================================
 * Level 5's rate limiter (a real one, backed by the database)
 * ===================================================================== */

/**
 * @return array{allowed:bool,used:int,limit:int,window:int}
 */
function gq_rate_check(string $ip, int $level, int $limit = 5, int $window = 60): array
{
    $db  = gq_db();
    $now = time();
    $db->prepare('DELETE FROM rate_hits WHERE ts < ?')->execute([$now - $window]);
    $st = $db->prepare('SELECT COUNT(*) c FROM rate_hits WHERE ip = ? AND level = ?');
    $st->execute([$ip, $level]);
    $used = (int)($st->fetch()['c'] ?? 0);

    if ($used >= $limit) {
        return ['allowed' => false, 'used' => $used, 'limit' => $limit, 'window' => $window];
    }
    $db->prepare('INSERT INTO rate_hits (ip, level, ts) VALUES (?,?,?)')->execute([$ip, $level, $now]);
    return ['allowed' => true, 'used' => $used + 1, 'limit' => $limit, 'window' => $window];
}
