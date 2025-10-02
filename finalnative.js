console.log("🔧 COLLECTING NATIVE ACTIVITY SEQUENCE");

var nativeLog = [];
var startTime = Date.now();

// Monitor thread creation
var initialThreads = Process.enumerateThreads().length;

setInterval(function() {
    var currentThreads = Process.enumerateThreads().length;
    if (currentThreads > initialThreads) {
        var entry = {
            time: new Date().toLocaleTimeString(),
            activity: "THREAD_CREATED",
            threadCount: currentThreads
        };
        nativeLog.push(entry);
        console.log("🔧 Native thread created - Total: " + currentThreads);
        initialThreads = currentThreads;
    }
}, 1000);

// Print sequence after 30 seconds
setTimeout(function() {
    console.log("\n📋 NATIVE ACTIVITY SEQUENCE:");
    if (nativeLog.length === 0) {
        console.log("No native activity detected");
    } else {
        nativeLog.forEach(function(entry, index) {
            console.log((index + 1) + ". " + entry.time + " - " + entry.activity + " - Threads: " + entry.threadCount);
        });
    }
}, 30000);

console.log("⏰ Monitoring native activity for 30 seconds...");