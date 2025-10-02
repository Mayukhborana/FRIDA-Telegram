# Automated security analysis tool that hooks into Telegram to monitor both Java API calls and native C++ function calls.
Bash Script (collect_run.sh)
Purpose: Automates the entire data collection process
<pre>
./collect_run.sh 21762
</pre>

* Starts Frida with both Java and native hooks

* Waits 4 seconds for hooks to initialize

**Either runs automated tests (monkey{ Google's built-in automated testing tool }) or waits 30 seconds for manual testing.**

# Java Hooks (java_host_decode.js)
Purpose: Monitors dangerous Android APIs and decodes data

Hooked Methods:
LocationManager.requestLocationUpdates - When app requests location

LocationManager.getLastKnownLocation - When app gets last known location

ContentResolver.query - When app reads contacts/database

FileInputStream.read / FileOutputStream.write - File operations

SmsManager.sendTextMessage - SMS sending

Camera.open - Camera access

MediaRecorder.start - Audio/video recording

Special Feature: Data Decoding
Converts byte arrays (like 60,63,120,109,108) back to readable text

Identifies file types (JPEG, XML, etc.) from byte patterns

Captures stack traces to see where calls come from

# Native Hooks (native_host.js)
Purpose: Monitors Telegram's C++ code

What it tries to do:
Find Telegram's native libraries (libtmessages.49.so, libtgvoip.so)

List exported functions from these libraries

Hook the first 8 functions from each library

Log when native functions are called with arguments


## Parse traces Results saved in the parsed_output directory!
<pre>
   python3 parse_traces.py tg_trace.jsonl tg_native_trace.jsonl
</pre>
captured:
✅ File operations - JPEG images, XML files being written
✅ Database queries - Reading contacts, media gallery
✅ Location access - GPS permission checks
✅ Camera usage - Photo operations
✅ Media operations - Audio/video processing { JPEG images (lines with -1,-40,-1,-32 = JPEG file header bytes)}
✅Evidence of Dangerous Permission Usage: 
* ContentResolver.query - Reading user data
* FileOutputStream.write - Writing files (potential data exfiltration)
* Location and camera APIs being called
✅Binary data (encrypted messages or media)

2. Database Queries - Telegram accessing your data:
ContentResolver.query - Reading contacts, messages, media

COUNT(_id) - Counting database records

bucket_display_name - Accessing photo gallery

Data Shows:
✅ File operations (JPEG, XML files)
✅ Database access (contacts, gallery)
✅ Permission checks
✅ Thread activity

Encrypted chats

Media processing

Your collection is successful - you're capturing real Telegram activity!
