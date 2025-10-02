// hooks/native_host.js
'use strict';
function logJSON(obj) { try { console.log(JSON.stringify(obj)); } catch(e){} }
function safePtrToStr(p) { try { return ptr(p).toString(); } catch(e) { return ''+p; } }

setTimeout(function(){
    try {
        var mods = Process.enumerateModulesSync();
        var candidates = mods.filter(function(m){
            var n = m.name.toLowerCase();
            return n.indexOf('libtg') !== -1 || n.indexOf('tmessages') !== -1 || n.indexOf('tgvoip') !== -1 || n.indexOf('telegram') !== -1;
        });
        if (candidates.length === 0) {
            mods.sort(function(a,b){ return b.size - a.size; });
            candidates = mods.slice(0,6);
        }
        console.log('[NATIVE_CAND] ' + candidates.map(function(m){ return m.name; }).join(', '));
        candidates.forEach(function(mod){
            try {
                var exps = Module.enumerateExportsSync(mod.name).filter(function(e){ return e.type === 'function' && e.name && e.name.length > 1; });
                exps.slice(0,8).forEach(function(exp){
                    try {
                        var addr = Module.findExportByName(mod.name, exp.name);
                        if (!addr) return;
                        Interceptor.attach(addr, {
                            onEnter: function(args) {
                                try {
                                    var trace = {
                                        ts: Date.now(),
                                        type: 'native',
                                        module: mod.name,
                                        func: exp.name,
                                        addr: safePtrToStr(addr),
                                        tid: this.threadId,
                                        arg0: safePtrToStr(args[0]),
                                        arg1: safePtrToStr(args[1])
                                    };
                                    logJSON(trace);
                                } catch (e) {}
                            }
                        });
                        console.log('[NTHOOK] ' + mod.name + '!' + exp.name);
                    } catch (e) {
                        console.log('[NTHOOK_ERR] ' + mod.name + '!' + exp.name + ' -> ' + e);
                    }
                });
            } catch (e) { console.log('[NAT_ENUM_ERR] ' + mod.name + ' -> ' + e); }
        });
    } catch (e) { console.log('[NATIVE_MAIN_ERR] ' + e); }
}, 1500);
