<?php
/**
 * NoSQL Injection Lab — Simulated MongoDB-style document store + query evaluator.
 *
 * This file emulates a Mongo document collection entirely in PHP. There is NO real
 * MongoDB server. `mongo_find($collection, $query)` walks the in-memory documents and
 * evaluates a Mongo-style query object supporting the operators:
 *
 *     $eq  $ne  $gt  $gte  $lt  $lte  $in  $nin  $regex  $exists  $where  $or  $and
 *
 * The teaching point of the lab is NOT this evaluator — it is that each level builds the
 * query object out of ATTACKER-CONTROLLED input without sanitising it, so an attacker can
 * smuggle operator objects (e.g. {"$ne": null}) into a field the developer expected to be
 * a plain scalar. This mirrors how real MongoDB drivers behave when a JSON body or a PHP
 * array query-string (password[$ne]=) is passed straight into db.users.find(...).
 */

/* =====================================================================
 * The document store (the "database").
 * The admin password is a long random secret so it can NEVER be guessed —
 * the ONLY way to authenticate as admin is to abuse a query operator.
 * For the blind-extraction levels (4, 7) the admin secret IS that level's
 * flag, so it must be recovered character-by-character via injection.
 * ===================================================================== */
function nosql_get_users(int $level = 0): array
{
    // Random, unguessable admin secret for the operator-bypass levels.
    $adminSecret = 'A9f!k27_Zx' . 'Qm4?b1Lp';

    // Blind levels store the FLAG itself as the admin's secret field.
    if ($level === 4) {
        $adminSecret = 'FLAG{nosql_regex_extraction}';
    } elseif ($level === 7) {
        $adminSecret = 'FLAG{nosql_blind_boolean}';
    }

    return [
        ['_id' => 1, 'username' => 'admin',   'password' => $adminSecret, 'role' => 'admin', 'email' => 'admin@corp.local'],
        ['_id' => 2, 'username' => 'alice',   'password' => 'alice_p@ss1', 'role' => 'user',  'email' => 'alice@corp.local'],
        ['_id' => 3, 'username' => 'bob',     'password' => 'bobbie2024',  'role' => 'user',  'email' => 'bob@corp.local'],
        ['_id' => 4, 'username' => 'guest',   'password' => 'guest',       'role' => 'user',  'email' => 'guest@corp.local'],
        ['_id' => 5, 'username' => 'auditor', 'password' => 'audit_secret','role' => 'user',  'email' => 'auditor@corp.local'],
    ];
}

/* =====================================================================
 * Public API: find documents matching a Mongo-style query object.
 * ===================================================================== */
function mongo_find(array $collection, $query): array
{
    if (!is_array($query)) {
        return [];
    }
    $out = [];
    foreach ($collection as $doc) {
        if (is_array($doc) && mongo_matches($doc, $query)) {
            $out[] = $doc;
        }
    }
    return $out;
}

/**
 * True when a single document satisfies every clause of the query.
 */
function mongo_matches(array $doc, array $query): bool
{
    foreach ($query as $key => $cond) {
        if ($key === '$or') {
            if (!is_array($cond)) return false;
            $ok = false;
            foreach ($cond as $sub) {
                if (is_array($sub) && mongo_matches($doc, $sub)) { $ok = true; break; }
            }
            if (!$ok) return false;
            continue;
        }
        if ($key === '$and') {
            if (!is_array($cond)) return false;
            foreach ($cond as $sub) {
                if (!is_array($sub) || !mongo_matches($doc, $sub)) return false;
            }
            continue;
        }
        if ($key === '$where') {
            if (!mongo_eval_where($doc, (string)$cond)) return false;
            continue;
        }

        $fieldVal = $doc[$key] ?? null;

        if (is_array($cond)) {
            // Operator object, e.g. {"$ne": null} or {"$regex": "^F"}
            if (!mongo_eval_operators($fieldVal, $cond)) return false;
        } else {
            // Implicit equality
            if (!nosql_eq($fieldVal, $cond)) return false;
        }
    }
    return true;
}

/* =====================================================================
 * Operator evaluation for a single field value.
 * ===================================================================== */
function mongo_eval_operators($fieldVal, array $cond): bool
{
    foreach ($cond as $op => $operand) {
        switch ($op) {
            case '$eq':
                if (!nosql_eq($fieldVal, $operand)) return false;
                break;
            case '$ne':
                if (nosql_eq($fieldVal, $operand)) return false;
                break;
            case '$gt':
                if (!nosql_cmp($fieldVal, $operand, '>'))  return false;
                break;
            case '$gte':
                if (!nosql_cmp($fieldVal, $operand, '>=')) return false;
                break;
            case '$lt':
                if (!nosql_cmp($fieldVal, $operand, '<'))  return false;
                break;
            case '$lte':
                if (!nosql_cmp($fieldVal, $operand, '<=')) return false;
                break;
            case '$in':
                if (!is_array($operand)) return false;
                $hit = false;
                foreach ($operand as $o) { if (nosql_eq($fieldVal, $o)) { $hit = true; break; } }
                if (!$hit) return false;
                break;
            case '$nin':
                if (is_array($operand)) {
                    foreach ($operand as $o) { if (nosql_eq($fieldVal, $o)) return false; }
                }
                break;
            case '$regex':
                if (!is_string($fieldVal)) return false;
                $opts  = isset($cond['$options']) && is_string($cond['$options']) ? $cond['$options'] : '';
                $flags = (strpos($opts, 'i') !== false ? 'i' : '');
                $pat   = '/' . str_replace('/', '\\/', (string)$operand) . '/' . $flags;
                if (@preg_match($pat, $fieldVal) !== 1) return false;
                break;
            case '$options':
                break; // consumed alongside $regex
            case '$exists':
                $exists = ($fieldVal !== null);
                if ((bool)$operand !== $exists) return false;
                break;
            default:
                // Unknown operator — a real Mongo query would error; treat as non-match.
                return false;
        }
    }
    return true;
}

/* =====================================================================
 * Comparison helpers (Mongo-ish, type-aware but tolerant of numeric strings).
 * ===================================================================== */
function nosql_eq($a, $b): bool
{
    if ($a === null || $b === null) {
        return $a === $b;
    }
    if (is_numeric($a) && is_numeric($b)) {
        return $a == $b;
    }
    return $a === $b;
}

function nosql_cmp($a, $b, string $op): bool
{
    if ($a === null) return false;
    if (is_numeric($a) && is_numeric($b)) { $a += 0; $b += 0; }
    switch ($op) {
        case '>':  return $a >  $b;
        case '>=': return $a >= $b;
        case '<':  return $a <  $b;
        case '<=': return $a <= $b;
    }
    return false;
}

/* =====================================================================
 * $where — JavaScript-style predicate evaluator.
 * Supports: numeric/string/boolean literals, this.<field>, comparison
 * operators (=== !== == != > < >= <=), logical && / ||, and parentheses.
 * NOTE: this is a small safe parser — it does NOT call eval().
 * ===================================================================== */
function mongo_eval_where(array $doc, string $js): bool
{
    $expr = trim($js);
    $expr = preg_replace('/^\s*return\s+/i', '', $expr);
    $expr = rtrim($expr, "; \t\n\r");
    if ($expr === '') return false;
    return nosql_where_expr($doc, $expr);
}

function nosql_where_expr(array $doc, string $expr): bool
{
    $expr = trim($expr);
    // Strip a single fully-wrapping parenthesis pair.
    while (strlen($expr) >= 2 && $expr[0] === '(' && substr($expr, -1) === ')'
           && nosql_parens_balanced(substr($expr, 1, -1))) {
        $expr = trim(substr($expr, 1, -1));
    }

    $ors = nosql_split_top($expr, '||');
    if (count($ors) > 1) {
        foreach ($ors as $o) { if (nosql_where_expr($doc, $o)) return true; }
        return false;
    }
    $ands = nosql_split_top($expr, '&&');
    if (count($ands) > 1) {
        foreach ($ands as $a) { if (!nosql_where_expr($doc, $a)) return false; }
        return true;
    }
    return nosql_where_atom($doc, $expr);
}

function nosql_where_atom(array $doc, string $atom): bool
{
    $atom = trim($atom);
    while (strlen($atom) >= 2 && $atom[0] === '(' && substr($atom, -1) === ')'
           && nosql_parens_balanced(substr($atom, 1, -1))) {
        $atom = trim(substr($atom, 1, -1));
    }
    if ($atom === '') return false;
    if (strcasecmp($atom, 'true')  === 0) return true;
    if (strcasecmp($atom, 'false') === 0) return false;

    foreach (['===', '!==', '==', '!=', '>=', '<=', '>', '<'] as $op) {
        $pos = nosql_find_top($atom, $op);
        if ($pos !== -1) {
            $l = nosql_where_val($doc, substr($atom, 0, $pos));
            $r = nosql_where_val($doc, substr($atom, $pos + strlen($op)));
            return nosql_where_cmp($l, $op, $r);
        }
    }

    // A bare atom with no comparison operator. If it does not resolve to a
    // literal or a document field it is a ReferenceError in real Mongo's JS
    // engine, so it must NOT quietly match every document — otherwise any
    // non-empty junk would "solve" the $where level without a predicate.
    $v = nosql_where_val($doc, $atom, $resolved);
    if (!$resolved)                return false;
    if (is_bool($v))               return $v;
    if (is_int($v) || is_float($v)) return $v != 0;
    if (is_string($v))             return $v !== '';
    return (bool)$v;
}

/**
 * Resolve one operand. $resolved is set false when the token is not a literal,
 * a document field or `this.<field>` — i.e. when the lenient "bare word becomes
 * a string" fallback had to be used. Comparisons stay lenient (so `role==admin`
 * works unquoted); only a standalone atom cares, because there an unresolvable
 * name is an error rather than a truthy value.
 */
function nosql_where_val(array $doc, string $t, ?bool &$resolved = null)
{
    $resolved = true;
    $t = trim($t);
    if ($t === '') return null;
    if (strlen($t) >= 2 &&
        (($t[0] === '"' && substr($t, -1) === '"') || ($t[0] === "'" && substr($t, -1) === "'"))) {
        return substr($t, 1, -1);
    }
    if (preg_match('/^-?\d+(\.\d+)?$/', $t)) return $t + 0;
    if (strcasecmp($t, 'true')  === 0) return true;
    if (strcasecmp($t, 'false') === 0) return false;
    if (strcasecmp($t, 'null')  === 0) return null;
    if (preg_match('/^this\.([A-Za-z_][A-Za-z0-9_]*)$/', $t, $m)) return $doc[$m[1]] ?? null;
    if (preg_match('/^([A-Za-z_][A-Za-z0-9_]*)$/', $t) && array_key_exists($t, $doc)) return $doc[$t];
    $resolved = false;
    return $t; // bare word → string literal
}

function nosql_where_cmp($l, $op, $r): bool
{
    switch ($op) {
        case '===': return $l === $r;
        case '!==': return $l !== $r;
        case '==':  return $l == $r;
        case '!=':  return $l != $r;
        case '>':   return $l >  $r;
        case '<':   return $l <  $r;
        case '>=':  return $l >= $r;
        case '<=':  return $l <= $r;
    }
    return false;
}

/**
 * Split a string on a delimiter that appears at the top level
 * (not inside quotes and not inside parentheses).
 */
function nosql_split_top(string $s, string $delim): array
{
    $parts = [];
    $buf = '';
    $depth = 0;
    $inStr = false;
    $q = '';
    $len = strlen($s);
    $dl = strlen($delim);
    for ($i = 0; $i < $len; $i++) {
        $ch = $s[$i];
        if ($inStr) {
            $buf .= $ch;
            if ($ch === $q && ($i === 0 || $s[$i - 1] !== '\\')) $inStr = false;
            continue;
        }
        if ($ch === '"' || $ch === "'") { $inStr = true; $q = $ch; $buf .= $ch; continue; }
        if ($ch === '(') { $depth++; $buf .= $ch; continue; }
        if ($ch === ')') { if ($depth > 0) $depth--; $buf .= $ch; continue; }
        if ($depth === 0 && $dl > 0 && substr($s, $i, $dl) === $delim) {
            $parts[] = $buf; $buf = ''; $i += $dl - 1; continue;
        }
        $buf .= $ch;
    }
    $parts[] = $buf;
    return $parts;
}

/**
 * Index of the first top-level occurrence of $needle, or -1.
 */
function nosql_find_top(string $s, string $needle): int
{
    $depth = 0;
    $inStr = false;
    $q = '';
    $len = strlen($s);
    $nl = strlen($needle);
    for ($i = 0; $i < $len; $i++) {
        $ch = $s[$i];
        if ($inStr) {
            if ($ch === $q && ($i === 0 || $s[$i - 1] !== '\\')) $inStr = false;
            continue;
        }
        if ($ch === '"' || $ch === "'") { $inStr = true; $q = $ch; continue; }
        if ($ch === '(') { $depth++; continue; }
        if ($ch === ')') { if ($depth > 0) $depth--; continue; }
        if ($depth === 0 && substr($s, $i, $nl) === $needle) return $i;
    }
    return -1;
}

function nosql_parens_balanced(string $s): bool
{
    $depth = 0;
    $inStr = false;
    $q = '';
    $len = strlen($s);
    for ($i = 0; $i < $len; $i++) {
        $ch = $s[$i];
        if ($inStr) {
            if ($ch === $q && ($i === 0 || $s[$i - 1] !== '\\')) $inStr = false;
            continue;
        }
        if ($ch === '"' || $ch === "'") { $inStr = true; $q = $ch; continue; }
        if ($ch === '(') $depth++;
        elseif ($ch === ')') { $depth--; if ($depth < 0) return false; }
    }
    return $depth === 0;
}

/* =====================================================================
 * Shared page helpers for the level files.
 * ===================================================================== */

/**
 * Safe JSON decode: returns [assoc-array|null, error-string].
 * Never throws; empty input returns [null, ''] (no error, no result).
 */
function nosql_json(string $raw): array
{
    $raw = trim($raw);
    if ($raw === '') return [null, ''];
    $decoded = json_decode($raw, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return [null, 'Invalid JSON: ' . json_last_error_msg()];
    }
    if (!is_array($decoded)) {
        return [null, 'The request body must be a JSON object.'];
    }
    return [$decoded, ''];
}

/**
 * True if any returned document has role "admin".
 */
function nosql_has_admin(array $results): bool
{
    foreach ($results as $r) {
        if (isset($r['role']) && $r['role'] === 'admin') return true;
    }
    return false;
}

/**
 * Pretty one-line-ish JSON echo of the query object actually executed.
 */
function nosql_query_repr($query): string
{
    if (!is_array($query)) return '(no query)';
    $json = json_encode($query, JSON_UNESCAPED_SLASHES);
    return $json === false ? '(unrepresentable query)' : $json;
}

/**
 * Recursively collect every operator key (any key beginning with "$") used
 * anywhere in a decoded query object. Used by the WAF levels to inspect input.
 */
function nosql_operators_used($query): array
{
    $ops = [];
    if (is_array($query)) {
        foreach ($query as $k => $v) {
            if (is_string($k) && isset($k[0]) && $k[0] === '$') {
                $ops[] = $k;
            }
            if (is_array($v)) {
                $ops = array_merge($ops, nosql_operators_used($v));
            }
        }
    }
    return array_values(array_unique($ops));
}

/**
 * Full-extraction check for the blind levels: confirms the attacker has pinned
 * the ENTIRE admin secret with an anchored ^...$ regex (or supplied it verbatim).
 * The secret lives only in the document store, so this rewards genuine extraction
 * rather than string-matching a hard-coded flag.
 */
function nosql_regex_fully_matches(string $regex, string $secret): bool
{
    if ($regex === '') return false;
    $start = ($regex[0] === '^');
    $end   = (substr($regex, -1) === '$');
    if (!$start || !$end) return false;
    $core = substr($regex, 1, -1);
    // Unescape common regex metacharacters so ^FLAG\{...\}$ compares to the raw secret.
    $core = preg_replace('/\\\\([\\{\\}\\[\\]\\(\\)\\.\\+\\*\\?\\^\\$\\|\\/\\\\])/', '$1', $core);
    return $core === $secret;
}
