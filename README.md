# Dynamic security analysis of the Telegram Android app using Frida
**Monitor dangerous permission APIs and native function calls.**

# Objectives:

Task 1: Identify dangerous permission APIs in Telegram
* hooked checkPermission and saw location permission checks

Task 2: Hook calls to dangerous permission APIs
* Detected android.permission.ACCESS_FINE_LOCATION being checked

Task 3: Identify native library used in the app
* Found libtmessages.49.so (Telegram's main native library)
 =Identify native libraries used by Telegram

Task 4: Identify native functions
* Detected native activity through thread creation

Task 5: Hook calls to native functions(Monitor native function execution)
* Monitored native library loading and thread creation

Task 6: Collect outputs and sequences
* have the sequence of events! (Collect sequence of API and native calls)
* Run tests and record outputs

# Tools Used
<pre>
Frida 17.3.2 - Dynamic instrumentation toolkit
Android Studio for emulator: Android Emulator - Testing environment
Telegram Android App - Target application
</pre>


# Setup:

**Prerequisites Installation**
<pre>
**Install ADB and Frida**
sudo apt install adb
pip install frida-tools
</pre>

**Frida Server Setup for Android ARM64**
<pre>
# Download Frida server 17.3.2 for ARM64
wget https://github.com/frida/frida/releases/download/17.3.2/frida-server-17.3.2-android-arm64.xz

# Extract the file
xz -d frida-server-17.3.2-android-arm64.xz

# Verify Frida installation
frida --version
frida-ps -U
</pre>

**Deploy Frida Server to Android**
<pre>
# Push to emulator
adb push frida-server-17.3.2-android-arm64 /data/local/tmp/frida-server

# Set executable permissions
adb shell "chmod 755 /data/local/tmp/frida-server"

# Verify file transfer
adb shell ls -l /data/local/tmp/frida-server || echo "no frida binary"
</pre>

**Start Frida Server**
<pre>
# Start Frida server in background
adb shell "nohup /data/local/tmp/frida-server >/data/local/tmp/frida.log 2>&1 & echo \$! > /data/local/tmp/frida.pid"

# Check if Frida server is running
adb shell "ps -A | grep -i frida || echo no-frida-process"
Output like this
root          7063     1   10866316  40060 do_sys_poll         0 S frida-server

# Verify Frida can see processes
frida-ps -U
Also Note the PID of Telegram.
</pre>




# Android Studio Emulator Setup
**Creating a Compatible Virtual Device**
* Open Android Studio
* Click on Virtual Device Manager
* Create a new virtual device:
* Select Pixel device (e.g., Pixel 4)
* Go to x86 Images tab
* Choose an x86_64 Google APIs image (Android 11/12 recommended)

**Important Notes:**
* Select Google APIs version, not Google Play Store version
* Google Play Store images are not rooted and may block Frida connections
* Google APIs images provide proper root access for Frida operation

**Installing Telegram on Emulator**
* Download Telegram APK on your computer

* Drag and drop the APK file onto the running emulator window

* The APK will automatically install on the emulator


# Experiments:

**Dangerous permission APIs hooked**
* Watches when Telegram asks for sensitive permissions like camera, location, contacts, etc
* Shows which permission was checked and whether it was granted or denied
* Records the time when each check happens

<pre>
frida -U -p 15341 -l dangerous_permissions.js > permissions_log.jsonl
</pre>

  <pre>
     ____
    / _  |   Frida 17.3.2 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Android Emulator 5554 (id=emulator-5554)
Attaching...                                                            
🔒 Hooking Dangerous Permissions
✅ Ready! Monitoring 5 dangerous permissions
[Android Emulator 5554::PID::8812 ]-> 🚨 DANGEROUS PERMISSION: android.permission.ACCESS_FINE_LOCATION
   Result: DENIED
   Time: 09:55:20 AM
🚨 DANGEROUS PERMISSION: android.permission.ACCESS_FINE_LOCATION
   Result: DENIED
   Time: 09:55:20 AM
  </pre>

Note(By manual clicks on The Telegram App):
* Location → You already tested (shows DENIED)

* Camera → Open chat → Camera icon

* Contacts → Contacts tab → Find friends

*  Microphone → Record voice message

* Files → Send a file





**Native library identified**
  <pre>
frida -U -p 8812 -l frida/findnativelibrary.js 
</pre>

 <pre>
Attaching...                                                            
🔍 Finding Native Library
📚 Loaded Native Libraries:
🎯 FOUND TELEGRAM LIBRARY: libtmessages.49.so
   Path: /data/app/~~ZDVMfK-p_FwfUr8YcELcHw==/org.telegram.messenger.web-YnEmyNKATIgYuHa_Q1AO7A==/lib/arm64/libtmessages.49.so
   Base: 0x7255046000
   Size: 28426240
</pre>

**Native functions hooked**
  <pre>
frida -U -p 8812 -l frida/native/hook_native_functions.js
  </pre>
 <pre>
✅ Monitoring for native library loading and thread creation...
📱 Use Telegram - when you see 'NATIVE LIBRARY LOADED', native code is running!
[Android Emulator 5554::PID::8812 ]-> 🎯 NATIVE LIBRARY LOADED: libtmessages.49.so
   Base: 0x7255046000
   Size: 28426240
🔧 NATIVE ACTIVITY: New thread created   
 </pre>

**For calls: Collection of permission**

Sequence of calls recorded

 <pre>
frida -U -p 15341 -l frida/finalcalls.js
 </pre>
 <pre>
Attaching...                                                            
🔒 COLLECTING PERMISSION SEQUENCE
⏰ Recording permission sequence for 30 seconds...
[Android Emulator 5554::PID::15341 ]-> 📝 android.permission.ACCESS_NETWORK_STATE - GRANTED
📝 android.permission.ACCESS_NETWORK_STATE - GRANTED
📝 android.permission.ACCESS_FINE_LOCATION - GRANTED
📝 android.permission.ACCESS_NETWORK_STATE - GRANTED
📝 android.permission.ACCESS_FINE_LOCATION - GRANTED
📝 com.google.android.providers.gsf.permission.READ_GSERVICES - GRANTED
📝 android.permission.CONFIGURE_WIFI_DISPLAY - DENIED
 
📋 PERMISSION CALL SEQUENCE:
1. 10:18:55 AM - android.permission.ACCESS_NETWORK_STATE - GRANTED
2. 10:18:55 AM - android.permission.ACCESS_NETWORK_STATE - GRANTED
3. 10:18:55 AM - android.permission.ACCESS_FINE_LOCATION - GRANTED
4. 10:18:55 AM - android.permission.ACCESS_NETWORK_STATE - GRANTED
5. 10:18:55 AM - android.permission.ACCESS_FINE_LOCATION - GRANTED
6. 10:18:57 AM - com.google.android.providers.gsf.permission.READ_GSERVICES - GRANTED
7. 10:19:03 AM - android.permission.CONFIGURE_WIFI_DISPLAY - DENIED
[Android Emulator 5554::PID::15341 ]-> exit

Thank you for using Frida!
 </pre>


 <pre>
frida -U -p 15341 -l final/finalnative.js 
 </pre>

  <pre>
     ____
    / _  |   Frida 17.3.2 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Android Emulator 5554 (id=emulator-5554)
Attaching...                                                            
🔧 COLLECTING NATIVE ACTIVITY SEQUENCE
⏰ Monitoring native activity for 30 seconds...
[Android Emulator 5554::PID::15341 ]-> 🔧 Native thread created - Total: 102
 </pre>

Both together:
 <pre>
 frida -U -p 15341 -l final/combine.js

  </pre>

  <pre>
     ____
    / _  |   Frida 17.3.2 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Android Emulator 5554 (id=emulator-5554)
Attaching...                                                            
🚀 COMBINED PERMISSION + NATIVE SEQUENCE
✅ Permission hook READY
⏰ Collecting BOTH permissions + native for 30 seconds...
📱 Test: Camera, Contacts, Location, Voice, Files in Telegram
[Android Emulator 5554::PID::15341 ]-> 🔧 NATIVE: libtmessages.49.so loaded

📊 COMBINED CALL SEQUENCE:
Total calls recorded: 1
1. 10:33:02 AM - NATIVE: libtmessages.49.so loaded

🎉 COMBINED SEQUENCE COMPLETE!
🔒 PERMISSION: android.permission.ACCESS_FINE_LOCATION
🔒 PERMISSION: android.permission.ACCESS_NETWORK_STATE
🔒 PERMISSION: android.permission.ACCESS_FINE_LOCATION
🔒 PERMISSION: android.permission.ACCESS_NETWORK_STATE
🚀 WORKING COMBINED SEQUENCE
✅ Permission hook ACTIVE
🎯 Recording STARTED!
💡 Type 'showResults()' to see sequence anytime
💡 Type 'stopRecording()' when done testing
🚀 WORKING COMBINED SEQUENCE
✅ Permission hook ACTIVE
🎯 Recording STARTED!
💡 Type 'showResults()' to see sequence anytime
💡 Type 'stopRecording()' when done testing
🚀 WORKING COMBINED SEQUENCE
✅ Permission hook ACTIVE
🎯 Recording STARTED!
💡 Type 'showResults()' to see sequence anytime
💡 Type 'stopRecording()' when done t

 </pre>

TO Do manual (when script is running):
While Frida is running, use Telegram to test:

Test 1 - Contacts Permission:

Open Telegram → Contacts → Sync contacts

Test 2 - Camera Permission:

Open a chat → Tap camera icon → Take photo

Test 3 - Location Permission:

Open a chat → Tap attachment → Location → Share location

Test 4 - Storage Permission:

Open a chat → Send a file/document

Test 5 - Audio Permission:

Make a voice call or send voice message
