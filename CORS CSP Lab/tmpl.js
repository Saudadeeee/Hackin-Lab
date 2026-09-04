/**
 * CORS CSP Lab · the client-side templating helper level 9 ships.
 *
 * It reads a template from the query string, pulls out every ${...}, runs two
 * checks over the text, and compiles what survives with new Function(). The
 * page's CSP allows that because it contains 'unsafe-eval'.
 *
 * jsexpr.php mirrors the two checks and the object graph so the server can
 * decide, honestly, whether an expression reached code execution.
 */
(function () {
    'use strict';

    /* Characters an interpolation may contain. */
    var ALLOW = /^[A-Za-z0-9_$.\[\]'"+\-*\/%() ]*$/;

    /* Names an interpolation may not mention. */
    var BANNED = ['eval', 'function', 'constructor', 'import', 'require',
                  'alert', 'document', 'window', 'settimeout', 'fetch'];

    function safeExpr(expr) {
        if (!ALLOW.test(expr)) {
            return false;
        }
        var low = expr.toLowerCase();
        for (var i = 0; i < BANNED.length; i++) {
            if (low.indexOf(BANNED[i]) !== -1) {
                return false;
            }
        }
        return true;
    }

    function render(tpl, d) {
        return tpl.replace(/\$\{([^}]*)\}/g, function (whole, expr) {
            if (!safeExpr(expr)) {
                return '[blocked: ' + expr + ']';
            }
            try {
                /* The sink. Reachable only because script-src carries 'unsafe-eval'. */
                return String(new Function('d', 'return (' + expr + ')')(d));
            } catch (e) {
                return '[error: ' + e.message + ']';
            }
        });
    }

    function boot() {
        var out = document.getElementById('out');
        if (!out) {
            return;
        }
        var params = new URLSearchParams(location.search);
        var tpl = params.get('t');
        if (!tpl) {
            tpl = 'Hello ${d.name}, you are on the ${d.plan} plan.';
        }
        out.textContent = render(tpl, { name: 'guest', plan: 'free', id: 41 });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
