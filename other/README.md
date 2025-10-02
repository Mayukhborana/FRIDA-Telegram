# Telegram Native Code Explorer
This script (telegram_hook.js) finds and analyzes Telegram's C++ code files to see what functions they contain.

* Find Telegram's C++ Files //Searches through all code files in the app

* Looks for files with "tmessages", "tg", or "telegram" in the name //Shows where they're located and how big they are

* List All Functions // Shows all available functions in the C++ files

* Displays the first 30 functions found //Shows each function's name and memory address

* Find Security-Related Functions //Filters for interesting security functions like:

  * encrypt / decrypt (data protection)

  * send / receive (network communication)

  * message / chat (message handling)

  * auth / key (authentication)


* Identifies specific native functions with addresses

Shows the structure of Telegram's C++ code

Provides function addresses for further analysis.






# Simple Explanation: Telegram Native Function Hooker
This script finds and hooks Telegram's C++ functions to monitor when they run.

What it does:
Step 1: Find Telegram's C++ Code
Locates libtmessages.49.so (Telegram's main C++ library)

Shows its location and size in memory

Step 2: Find Functions by Pattern Matching
Scans the C++ code for common function patterns (ARM64 code signatures)

When it finds something that looks like a function, it hooks it

Gives them names like unknown_function_0x7255061234

Step 3: Hook System Functions
Also hooks basic system functions that Telegram definitely uses:

open, read, write (file operations)

socket, connect (network operations)










