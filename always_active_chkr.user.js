// ==UserScript==
// @name         Always Active - chkr.cc
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Сайт всегда думает что ты на вкладке
// @match        *://chkr.cc/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(function() {
    'use strict';

    // 1. Page Visibility API — сайт всегда "visible"
    Object.defineProperty(document, 'visibilityState', {get: () => 'visible'});
    Object.defineProperty(document, 'hidden', {get: () => false});

    // 2. Блокируем blur и visibilitychange обработчики сайта
    const origAdd = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function(type, fn, ...args) {
        if (type === 'blur' || type === 'visibilitychange') return;
        return origAdd.call(this, type, fn, ...args);
    };

    // 3. Перехватываем blur событие на window (через оригинальный addEventListener)
    origAdd.call(window, 'blur', e => e.stopImmediatePropagation(), true);
    origAdd.call(document, 'visibilitychange', e => e.stopImmediatePropagation(), true);

    // 4. Периодически генерируем фейковые focus/mousemove чтобы сайт думал что мы активны
    function fakeActivity() {
        const events = ['focus', 'mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart'];
        events.forEach(type => {
            window.dispatchEvent(new Event(type, {bubbles: true, cancelable: true}));
        });
    }

    // 5. Подмена requestAnimationFrame — не замораживается в фоне
    window.requestAnimationFrame = function(cb) {
        return setTimeout(cb, 16);
    };
    window.cancelAnimationFrame = function(id) {
        clearTimeout(id);
    };

    // 6. Web Worker для точных интервалов (не throttling'ается браузером)
    const workerCode = `
        let intervalId = null;
        self.onmessage = function(e) {
            if (e.data.command === 'start') {
                intervalId = setInterval(() => self.postMessage('tick'), e.data.interval || 1000);
            } else if (e.data.command === 'stop') {
                clearInterval(intervalId);
            }
        };
    `;
    const workerBlob = new Blob([workerCode], {type: 'application/javascript'});
    const workerUrl = URL.createObjectURL(workerBlob);
    const worker = new Worker(workerUrl);

    // Каждые 500мс — фейковая активность через Worker (не тормозит в фоне)
    worker.postMessage({command: 'start', interval: 500});
    worker.onmessage = function() {
        fakeActivity();
    };

    // 7. Подмена document.hasFocus()
    document.hasFocus = function() { return true; };

    // 8. При загрузке DOM — сразу фейковый focus
    if (document.readyState === 'loading') {
        origAdd.call(document, 'DOMContentLoaded', () => fakeActivity());
    } else {
        fakeActivity();
    }

    console.log('[Always Active] Скрипт загружен — сайт всегда думает что ты тут');
})();
