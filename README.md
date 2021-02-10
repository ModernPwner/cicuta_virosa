# cicuta_virosa
iOS\iPadOS 14.3 kernel LPE for all devices by **@ModernPwner**. Please follow me on twitter :)

# Current state
- Exploit works :)
- Need a lot of cleanup + more stable primitives that not relaying on memory reallocation. **Use it on your own risk**
- Exploit will take more then 2 minutes because I can't understand how to properly bypass one stupid sanity check in kernel on "Stage 3: Convert uaf into pktopts uaf" (I will fix it soon)
- Reliability is amazing on my A13 device

# The vuln
Impact: A malicious application may be able to elevate privileges. Apple is aware of a report that this issue may have been actively exploited.  
Description: A race condition was addressed with improved locking.  
CVE-2021-1782

# Writeup
Soon.

# How to build it
I don't like to commit Xcode project file. Create your own XCode project, add files and call "cicuta_virosa" function.

# Credits
- Some utils (exploit_utilities.c): @Jakeashacks
- Vuln: Apple

# License
If you want to use it in your project under GPL not-compatible license - **please** DM me to get permissions.  
I give permissions to **@CStar_OW** to use and modify the exploit for Odyssey - the best jailbreak :).  
But I hope that all modifications will be open sourced.  
