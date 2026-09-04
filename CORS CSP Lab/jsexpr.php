<?php
/**
 * CORS CSP Lab · a miniature JavaScript expression evaluator.
 *
 * Level 9 ships a client-side templating helper (tmpl.js) that hands the text
 * between ${ and } to new Function(). To award the flag for the *effect* rather
 * than for a payload shape, the server has to answer the same question the
 * browser answers: does this expression actually reach code execution?
 *
 * So this file evaluates the expression for real, over a tiny object graph that
 * mirrors the one tmpl.js exposes. It supports exactly the grammar the gadget
 * can produce:
 *
 *   expr    := unary (('+'|'-'|'*'|'/'|'%') unary)*
 *   unary   := primary trailer*
 *   trailer := '.' IDENT | '[' expr ']' | '(' args ')'
 *   primary := STRING | NUMBER | IDENT | '(' expr ')'
 *
 * The object graph models the three JavaScript facts the level depends on:
 *   ''.constructor            is String
 *   (any function).constructor is Function
 *   Function('...')            returns a callable that runs that source
 *
 * Anything outside the grammar raises an error, and the level prints it. The
 * evaluator never inspects the payload for keywords - it runs it.
 */

/* =========================================================================
 * The gadget's own parsing and filter, mirrored from tmpl.js
 * ===================================================================== */

/** Characters tmpl.js permits inside an interpolation. Keep in sync with tmpl.js. */
const TMPL_ALLOW = '~^[A-Za-z0-9_$.\[\]\'"+\-*/%() ]*$~';

/** Substrings tmpl.js refuses, case-insensitively. Keep in sync with tmpl.js. */
function tmpl_banned_words(): array
{
    return ['eval', 'function', 'constructor', 'import', 'require',
            'alert', 'document', 'window', 'settimeout', 'fetch'];
}

/** Every ${...} the gadget's own regex would pick out of a template. */
function tmpl_extract(string $template): array
{
    preg_match_all('~\$\{([^}]*)\}~', $template, $m);
    return $m[1] ?? [];
}

/**
 * The gadget's filter. Returns ['ok'=>bool, 'reason'=>string].
 */
function tmpl_filter(string $expr): array
{
    if (!preg_match(TMPL_ALLOW, $expr)) {
        return ['ok' => false, 'reason' => 'The expression contains a character outside the allowed set.'];
    }
    $low = strtolower($expr);
    foreach (tmpl_banned_words() as $w) {
        if (strpos($low, $w) !== false) {
            return ['ok' => false, 'reason' => 'The expression contains the banned substring "' . $w . '".'];
        }
    }
    return ['ok' => true, 'reason' => 'Passed both checks and is handed to new Function().'];
}

/* =========================================================================
 * Values
 * ===================================================================== */

function js_fn(string $name, bool $code = false): array
{
    return ['__t' => 'fn', 'name' => $name, 'code' => $code, 'source' => ''];
}

function js_obj(array $props): array
{
    return ['__t' => 'obj', 'props' => $props];
}

function js_type($v): string
{
    if (is_array($v) && isset($v['__t'])) {
        return $v['__t'];
    }
    if (is_string($v)) {
        return 'string';
    }
    if (is_int($v) || is_float($v)) {
        return 'number';
    }
    return 'undefined';
}

function js_show($v): string
{
    switch (js_type($v)) {
        case 'fn':       return 'function ' . $v['name'] . ($v['code'] ? ' (compiled from your source)' : '');
        case 'obj':      return 'object {' . implode(', ', array_keys($v['props'])) . '}';
        case 'executed': return 'the compiled function ran';
        case 'string':   return "'" . $v . "'";
        case 'number':   return (string)$v;
        default:         return 'undefined';
    }
}

/** The `d` object tmpl.js passes into the compiled function. */
function js_template_data(): array
{
    return js_obj([
        'name' => 'guest',
        'plan' => 'free',
        'id'   => 41,
    ]);
}

/* =========================================================================
 * Evaluator
 * ===================================================================== */

final class JsExprError extends Exception
{
}

final class JsExpr
{
    private string $s;
    private int $i = 0;
    private int $n;

    /** Set to true the moment a compiled function is actually invoked. */
    public bool $executed = false;

    /** Source text handed to the Function constructor, when that happened. */
    public string $compiled = '';

    /** Human-readable steps, used to build the pipeline trace. */
    public array $trace = [];

    public function __construct(string $src)
    {
        $this->s = $src;
        $this->n = strlen($src);
    }

    public function run()
    {
        $v = $this->parseBinary();
        $this->ws();
        if ($this->i < $this->n) {
            throw new JsExprError('Unexpected "' . $this->s[$this->i] . '" at position ' . $this->i . '.');
        }
        return $v;
    }

    /* ---- lexing helpers ---- */

    private function ws(): void
    {
        while ($this->i < $this->n && ($this->s[$this->i] === ' ' || $this->s[$this->i] === "\t")) {
            $this->i++;
        }
    }

    private function peek(): string
    {
        $this->ws();
        return $this->i < $this->n ? $this->s[$this->i] : '';
    }

    private function eat(string $ch): void
    {
        if ($this->peek() !== $ch) {
            throw new JsExprError('Expected "' . $ch . '" at position ' . $this->i . '.');
        }
        $this->i++;
    }

    /* ---- grammar ---- */

    private function parseBinary()
    {
        $left = $this->parseUnary();
        while (true) {
            $c = $this->peek();
            if ($c === '' || strpos('+-*/%', $c) === false) {
                return $left;
            }
            $this->i++;
            $right = $this->parseUnary();
            $left  = $this->binary($c, $left, $right);
        }
    }

    private function binary(string $op, $a, $b)
    {
        if ($op === '+') {
            if (is_string($a) || is_string($b)) {
                return $this->toStr($a) . $this->toStr($b);
            }
            return $a + $b;
        }
        if (!is_numeric($a) || !is_numeric($b)) {
            throw new JsExprError('Arithmetic "' . $op . '" needs two numbers.');
        }
        switch ($op) {
            case '-': return $a - $b;
            case '*': return $a * $b;
            case '/': return $b == 0 ? INF : $a / $b;
            default:  return $b == 0 ? NAN : fmod($a, $b);
        }
    }

    private function toStr($v): string
    {
        return is_string($v) ? $v : (is_int($v) || is_float($v) ? (string)$v : js_show($v));
    }

    private function parseUnary()
    {
        $v = $this->parsePrimary();
        while (true) {
            $c = $this->peek();
            if ($c === '.') {
                $this->i++;
                $this->ws();
                if (!preg_match('~\G[A-Za-z_$][A-Za-z0-9_$]*~', $this->s, $m, 0, $this->i)) {
                    throw new JsExprError('Expected a property name after "." at position ' . $this->i . '.');
                }
                $this->i += strlen($m[0]);
                $v = $this->member($v, $m[0]);
            } elseif ($c === '[') {
                $this->i++;
                $key = $this->parseBinary();
                $this->eat(']');
                $v = $this->member($v, $this->toStr($key));
            } elseif ($c === '(') {
                $this->i++;
                $args = [];
                if ($this->peek() !== ')') {
                    $args[] = $this->parseBinary();
                    while ($this->peek() === ',') {
                        $this->i++;
                        $args[] = $this->parseBinary();
                    }
                }
                $this->eat(')');
                $v = $this->call($v, $args);
            } else {
                return $v;
            }
        }
    }

    private function parsePrimary()
    {
        $c = $this->peek();
        if ($c === '') {
            throw new JsExprError('The expression ended where a value was expected.');
        }
        if ($c === "'" || $c === '"') {
            return $this->parseString($c);
        }
        if (ctype_digit($c)) {
            preg_match('~\G[0-9]+(\.[0-9]+)?~', $this->s, $m, 0, $this->i);
            $this->i += strlen($m[0]);
            return strpos($m[0], '.') !== false ? (float)$m[0] : (int)$m[0];
        }
        if ($c === '(') {
            $this->i++;
            $v = $this->parseBinary();
            $this->eat(')');
            return $v;
        }
        if (preg_match('~\G[A-Za-z_$][A-Za-z0-9_$]*~', $this->s, $m, 0, $this->i)) {
            $this->i += strlen($m[0]);
            if ($m[0] === 'd') {
                return js_template_data();
            }
            throw new JsExprError('"' . $m[0] . '" is not defined inside the template scope. '
                                . 'The compiled function only receives d.');
        }
        throw new JsExprError('Unexpected character "' . $c . '" at position ' . $this->i . '.');
    }

    private function parseString(string $quote): string
    {
        $this->i++;                       // opening quote
        $out = '';
        while ($this->i < $this->n && $this->s[$this->i] !== $quote) {
            $out .= $this->s[$this->i++];
        }
        if ($this->i >= $this->n) {
            throw new JsExprError('Unterminated string literal.');
        }
        $this->i++;                       // closing quote
        return $out;
    }

    /* ---- the object graph ---- */

    private function member($obj, string $key)
    {
        $t = js_type($obj);

        if ($t === 'string') {
            if ($key === 'constructor') {
                $this->trace[] = "reading .constructor on a string yields the String function";
                return js_fn('String');
            }
            if ($key === 'length') {
                return strlen($obj);
            }
            return null;
        }
        if ($t === 'fn') {
            if ($key === 'constructor') {
                $this->trace[] = "reading .constructor on function {$obj['name']} yields the Function constructor";
                return js_fn('Function');
            }
            if ($key === 'name') {
                return $obj['name'];
            }
            return null;
        }
        if ($t === 'obj') {
            if (array_key_exists($key, $obj['props'])) {
                return $obj['props'][$key];
            }
            if ($key === 'constructor') {
                $this->trace[] = 'reading .constructor on a plain object yields the Object function';
                return js_fn('Object');
            }
            return null;
        }
        throw new JsExprError('Cannot read property "' . $key . '" of ' . js_show($obj) . '.');
    }

    private function call($fn, array $args)
    {
        if (js_type($fn) !== 'fn') {
            throw new JsExprError(js_show($fn) . ' is not a function.');
        }
        if (!empty($fn['code'])) {
            $this->executed = true;
            $this->trace[]  = 'calling the compiled function runs the source you supplied';
            return ['__t' => 'executed'];
        }
        switch ($fn['name']) {
            case 'Function':
                $src = $args ? $this->toStr($args[0]) : '';
                $this->compiled = $src;
                $this->trace[]  = 'Function(' . ($src === '' ? '' : "'" . $src . "'") . ') compiles that string into a callable';
                $f = js_fn('anonymous', true);
                $f['source'] = $src;
                return $f;
            case 'String':
                return $args ? $this->toStr($args[0]) : '';
            case 'Object':
                return js_obj([]);
            default:
                throw new JsExprError('function ' . $fn['name'] . ' cannot be called here.');
        }
    }

    /**
     * Evaluate one interpolation expression.
     *
     * @return array{ok:bool, value:mixed, executed:bool, compiled:string, trace:string[], error:string}
     */
    public static function evaluate(string $expr): array
    {
        $ev = new self($expr);
        try {
            $value = $ev->run();
            return ['ok' => true, 'value' => $value, 'executed' => $ev->executed,
                    'compiled' => $ev->compiled, 'trace' => $ev->trace, 'error' => ''];
        } catch (JsExprError $e) {
            return ['ok' => false, 'value' => null, 'executed' => $ev->executed,
                    'compiled' => $ev->compiled, 'trace' => $ev->trace, 'error' => $e->getMessage()];
        }
    }
}
