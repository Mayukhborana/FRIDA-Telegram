Some 


Simple Explanation: Telegram Native Code Explorer
This script finds and analyzes Telegram's C++ code files to see what functions they contain.

What it does:
Step 1: Find Telegram's C++ Files
Searches through all code files in the app

Looks for files with "tmessages", "tg", or "telegram" in the name

Shows where they're located and how big they are

Step 2: List All Functions
Shows all available functions in the C++ files

Displays the first 30 functions found

Shows each function's name and memory address

Step 3: Find Security-Related Functions
Filters for interesting security functions like:

encrypt / decrypt (data protection)

send / receive (network communication)

message / chat (message handling)

auth / key (authentication)


Why this matters for your assignment:
Identifies specific native functions for Task 4

Finds security-related functions you can hook

Shows the structure of Telegram's C++ code

Provides function addresses for further analysis





