console.log("Starting Permission Monitor");

Java.perform(function() {
    // Permissions to watch
    var dangerous = [
        "android.permission.READ_CONTACTS",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION", 
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_EXTERNAL_STORAGE"
    ];

    var Activity = Java.use("android.app.Activity");
    
    Activity.checkPermission.overload('java.lang.String', 'int', 'int').implementation = function(permission, pid, uid) {
        var result = this.checkPermission(permission, pid, uid);
        
        if (dangerous.includes(permission)) {
            // Create JSON object
            var logEntry = {
                "type": "PERMISSION_CHECK",
                "permission": permission,
                "result": result === 0 ? "GRANTED" : "DENIED",
                "timestamp": new Date().toISOString(),
                "pid": pid,
                "uid": uid
            };
            
            // Print as JSONL (JSON Lines format)
            console.log(JSON.stringify(logEntry));
        }
        
        return result;
    };

    console.log("Permission monitor ready");
});