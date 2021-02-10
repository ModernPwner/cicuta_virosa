# cicuta_virosa
iOS\iPadOS 14.3 kernel LPE for all devices by **@ModernPwner**. Please follow us on twitter :)

# Current state
- Exploit works :)
- Need a lot of cleanup + more stable primitives that not relaying on memory reallocation. **Use it on your own risk**
- Exploit will take more then 2 minutes because we can't understand how to properly bypass one stupid sanity check in kernel on "Stage 3: Convert uaf into pktopts uaf" (we'll fix it soon)
- Reliability is amazing on our A13 and A10 devices

# The vuln
**CVE-2021-1782**: A race condition in user_data_get_value() leading to ivac entry uaf. This issue has been actively exploited in the wild with the WebKit exploit. We might release this RCE chain in the future.

# Writeup
Soon.

# How to build it
We don't like to commit Xcode project file. Create your own XCode project, add files and call "cicuta_virosa" function.

# Credits
- Some utils (exploit_utilities.c): @Jakeashacks
- Vuln: Apple

# License
If you want to use it in your project under GPL not-compatible license - **please** DM us to get permissions.  
We give permissions to **@CStar_OW** to use and modify the exploit for Odyssey - the best jailbreak :).  
But we hope that all modifications will be open sourced.  

# PAC bypass
For the moment we have a brand new technique to bypass PAC but we decided to not include such critical stuff here.  
**Maybe** we'll post a PAC bypass along with the iOS 14.5 exploit. This is in progress, we **may** publish 14.5 exploit after Apple patch. 
