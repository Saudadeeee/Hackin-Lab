/**
 * The storefront's own widget, loaded by render.php with a RELATIVE path.
 * Its only job in level 8 is to be the script whose URL an injected <base>
 * can move somewhere else.
 */
(function () {
    var el = document.getElementById('hlab-status');
    if (el) {
        el.textContent = 'app/widget.js loaded from the page own origin - nothing was hijacked';
    }
})();
