/**
 * CORS CSP Lab · the module bootstrapper level 10 ships.
 *
 * This is the shape RequireJS has used for years: a loader script reads a
 * data-main attribute off an element and turns it into a script src. Under a
 * normal host allowlist that is unremarkable, because the resulting URL still
 * has to match the allowlist. Under 'strict-dynamic' the allowlist is not
 * consulted at all for scripts a trusted script inserts, so this attribute is
 * as powerful as the nonce itself.
 */
(function () {
    'use strict';

    function boot() {
        var el = document.querySelector('[data-main]');
        if (!el) {
            return;
        }
        var s = document.createElement('script');
        s.src = el.getAttribute('data-main');   // taken verbatim, no validation
        s.async = true;
        document.head.appendChild(s);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
