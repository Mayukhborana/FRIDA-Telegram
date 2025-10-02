// hooks/java_host_decode.js
'use strict';
const MAX_ARG_STR_LEN = 300;
const MAX_DECODE_BYTES = 512;

function isPrintables(b) {
    var printable = 0;
    for (var i = 0; i < b.length; i++) {
        if (b[i] >= 9 && b[i] <= 126) printable++;
    }
    return (printable / b.length) > 0.8;
}

function tryDecodeBytesFromStringRepresentation(s) {
    try {
        if (!s || typeof s !== 'string') return null;
        var arr = s.split(',').map(function(x){ x = x.trim(); return /^\-?\d+$/.test(x) ? (parseInt(x) & 0xff) : NaN; }).filter(function(n){ return !isNaN(n); });
        if (arr.length === 0 || arr.length > MAX_DECODE_BYTES) return null;
        var b = new Uint8Array(arr);
        if (!isPrintables(b)) return null;
        try {
            var decoder = new TextDecoder('utf-8');
            return decoder.decode(b);
        } catch (e) {
            try { return String.fromCharCode.apply(null, Array.prototype.slice.call(b,0,Math.min(b.length,200))); } catch(e2){ return null; }
        }
    } catch (e) { return null; }
}

function safeToString(obj) {
    try {
        if (obj === null || obj === undefined) return null;
        if (typeof obj === 'string' || typeof obj === 'number' || typeof obj === 'boolean') {
            var s = '' + obj;
            return (s.length > MAX_ARG_STR_LEN) ? s.slice(0, MAX_ARG_STR_LEN) + '...' : s;
        }
        if (obj && obj.getClass) {
            try {
                var cls = obj.getClass().getName();
                var id = java.lang.System.identityHashCode(obj);
                if (cls === '[B') {
                    try {
                        var len = obj.length;
                        var out = [];
                        var capped = Math.min(len, 256);
                        for (var i = 0; i < capped; i++) out.push((obj[i] & 0xff));
                        if (len > capped) out.push('...');
                        return out.join(',');
                    } catch(e) { return `<Java:${cls} id=${id}>`; }
                }
                return `<Java:${cls} id=${id}>`;
            } catch(e) {
                return '<Java:unserializable>';
            }
        }
        return String(obj).slice(0, MAX_ARG_STR_LEN);
    } catch (e) {
        return '<toString-failed>';
    }
}

function logJSON(obj) {
    try { console.log(JSON.stringify(obj)); } catch (e) { try { console.log('[LOG_ERR] ' + e); } catch(_) {} }
}

Java.perform(function () {
    var Thread = Java.use('java.lang.Thread');

    function hookMethod(className, methodName) {
        try {
            var cls = Java.use(className);
            if (!cls[methodName]) { console.log('[HOOK_NA] ' + className + '.' + methodName + ' not found'); return; }
            cls[methodName].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    try {
                        var rawArgs = Array.prototype.slice.call(arguments);
                        var args = rawArgs.map(safeToString);
                        var trace = {
                            ts: Date.now(),
                            type: 'java',
                            class: className,
                            method: methodName,
                            args: args,
                            thread: Thread.currentThread().getName()
                        };
                        if (args.length > 0 && typeof args[0] === 'string' && args[0].indexOf(',') !== -1) {
                            var dec = tryDecodeBytesFromStringRepresentation(args[0]);
                            if (dec) trace.payload_text = dec;
                        }
                        try { trace.stack0 = Thread.currentThread().getStackTrace()[2].toString(); } catch(e){}
                        logJSON(trace);
                    } catch (hookErr) {
                        console.log('[HOOK_ERR] ' + className + '.' + methodName + ' -> ' + hookErr);
                    }
                    return ov.apply(this, arguments);
                };
            });
            console.log('[HOOKED] ' + className + '.' + methodName);
        } catch (e) { console.log('[HOOK_FAIL] ' + className + '.' + methodName + ' -> ' + e); }
    }

    // Dangerous / interesting APIs
    hookMethod('android.location.LocationManager', 'requestLocationUpdates');
    hookMethod('android.location.LocationManager', 'getLastKnownLocation');
    hookMethod('android.content.ContentResolver', 'query');
    hookMethod('java.io.FileInputStream', 'read');
    hookMethod('java.io.FileOutputStream', 'write');
    hookMethod('android.telephony.SmsManager', 'sendTextMessage');
    hookMethod('android.hardware.Camera', 'open');
    hookMethod('android.media.MediaRecorder', 'start');
});
