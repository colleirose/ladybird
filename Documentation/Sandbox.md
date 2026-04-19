# Ladybird sandboxing
Ladybird implements strong sandboxing to isolate the browser from the rest of the system as much as possible so that, even if the browser was compromised, it wouldn't have control over the rest of the system. This makes it significantly safer to run complex, attacker-controlled website scripts because obtaining access to the rest of the system would require a vulnerability not just in the browser, but also in the limited operating functions exposed to it.

The sandboxing implementation takes some inspiration from, but is not copied from, [the Chromium sandboxing implementation](https://github.com/chromium/chromium/blob/3bd6b30329f89b12709c03f6b6cb7a3c17dd0539/sandbox) and [the Firefox sandboxing implementation](https://github.com/mozilla-firefox/firefox/tree/f3d29c586150a019fa9ed3352a2111d52ee54fc5/security/sandbox). Almost all of the code we take inspiration from here is specifically for Windows sandboxing. This is because Windows sandboxing depends on many complex, poorly-documented functions with [obscure quirks that have led to sandbox escapes](https://bugzilla.mozilla.org/show_bug.cgi?id=1956398), and so for safety we should take advantage of the detailed research and testing of proprietary Windows APIs done by Google and Mozilla.

This code is far from complete, and there is nothing for MacOS, Android, or BSD yet. A lot needs to be done to implement stronger sandboxing and improve the overall security hardening, but the code so far is a good starting point.

Please try to keep this file updated when any important changes are made to the sandboxing system.

## How sandboxing is currently implemented
### Linux
- libseccomp is used to implement seccomp filters
- bubblewrap is used for sandboxing based on user namespace and setuid
## Windows
- The [AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-for-legacy-applications-) API is used to directly isolate the program from the rest of the system and is similar to how Microsoft Store/UWP apps are sandboxed.
- Several [process mitigation policies](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy) are enabled to reduce attack surface and to provide hardening against memory corruption and other exploits. Similarly, [HeapEnableTerminateOnCorruption](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapsetinformation) is turned on to automatically abort the program if Windows detects heap corruption.
- An [alternative desktop object](https://chromium.googlesource.com/chromium/src/+/master/docs/design/sandbox.md#The-alternate-desktop) is set to isolate the program from other windows on the system to prevent the [shatter attacks](https://en.wikipedia.org/wiki/Shatter_attack) affecting Windows.

## What other changes need to be made
### Windows
- [Restricting Win32k syscalls](https://projectzero.google/2016/11/breaking-chain.html)
- Using [the Job object](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) to allow restricting some more obscure features (like [the clipboard and some UI features](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_ui_restrictions))
- Stronger AppContainer restrictions. Most processes have filesystem and network access right now.
### MacOS
- Implement MacOS sandboxing
### Android
- Implement Android sandboxing
### BSD
- Implement BSD sandboxing
### Linux
- Sandboxing with [Landlock](https://landlock.io/)
- Reducing the amount of syscalls allowed in seccomp
- Sandboxing with namespaces and chroot directly (no bubblewrap usage)
- When the application is running under Flatpak, use `flatpak spawn --sandbox` to create sandboxed child processes

## Resources
### General
- https://madaidans-insecurities.github.io/firefox-chromium.html (kind of outdated and inaccurate, but explains mitigations and sandboxing well enough)
- https://github.com/mozilla-firefox/firefox/tree/main/security/sandbox
- https://github.com/chromium/chromium/tree/main/sandbox

### Windows
- *Windows Internals, Part 1, 7th Edition* book by Microsoft
- *Windows Internals, Part 2, 7th Edition* book by Microsoft
- https://chromium.googlesource.com/chromium/src/+/master/docs/design/sandbox.md (Chromium Windows sandboxing, partially outdated)
- https://media.blackhat.com/bh-us-12/Briefings/M_Miller/BH_US_12_Miller_Exploit_Mitigation_Slides.pdf (Windows security mitigations presentation)

### Linux
- https://github.com/chromium/chromium/blob/main/sandbox/linux/README.md (Chromium Linux sandboxing design document, partially outdated)

### Android
- https://developer.android.com/guide/topics/manifest/service-element#isolated
- https://github.com/chromium/chromium/blob/main/docs/security/android-sandbox.md

### OSX
- https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox (Apple official MacOS sandboxing documentation)
- https://www.chromium.org/developers/design-documents/sandbox/osx-sandboxing-design/ (Chromium MacOS sandboxing documentation, don't know how recent)
