/*
   irscan - bundled detection rules
   ---------------------------------
   These rules are written for irscan and licensed under the same terms as the
   project (MIT OR Apache-2.0).

   Design notes that matter when reading them:

   * A YARA match is a *lead*, not a verdict. Every rule below can match
     legitimate software; what makes a match worth investigating is the pairing
     with the other evidence irscan collects - an unusual path, an untrusted
     signature, a listening socket, a scheduled task. The `severity` metadata is
     therefore deliberately conservative, and the collector reports the file it
     matched so a human can look at it.
   * The API-set rules match a *combination* of symbols rather than a single
     string. One symbol proves nothing; a binary that contains the whole set for
     capturing the screen, or for injecting input, is doing something that
     deserves a second look.
   * `severity` is read by irscan: critical|high -> HIGH, medium -> MED,
     low|info -> INFO. `description` is shown as evidence.
   * The API-set rules are marked `low` on purpose. They match ordinary software -
     browsers, chat clients, torrent clients all contain BitBlt and SendInput - so
     raising them above INFO would train the reader to ignore the report. What makes
     one of those matches worth following up is the *combination* with the other
     evidence irscan collects: the path it runs from, its signature, its sockets.
*/

rule irscan_input_injection_api_set
{
    meta:
        author = "irscan contributors"
        description = "Contains the API set used to synthesise keyboard and mouse input. This is how a remote operator moves the pointer; it is also how accessibility tools and automation do it, so treat it as a lead, not a verdict."
        severity = "low"
        reference = "matches the reported symptom: the pointer moved on its own"
    strings:
        $a1 = "SendInput" ascii
        $a2 = "mouse_event" ascii
        $a3 = "SetCursorPos" ascii
        $a4 = "keybd_event" ascii
        $a5 = "SendMessageTimeout" ascii
        $a6 = "PostMessage" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule irscan_screen_capture_api_set
{
    meta:
        author = "irscan contributors"
        description = "Contains the classic GDI screen-capture API set. Monitoring agents and stalkerware screenshot the desktop this way; so do screenshot utilities."
        severity = "low"
    strings:
        $a1 = "BitBlt" ascii
        $a2 = "CreateCompatibleBitmap" ascii
        $a3 = "GetDeviceCaps" ascii
        $a4 = "GetSystemMetrics" ascii
        $a5 = "StretchBlt" ascii
        $a6 = "CreateDIBSection" ascii
    condition:
        uint16(0) == 0x5A4D and 4 of them
}

rule irscan_keylogger_api_set
{
    meta:
        author = "irscan contributors"
        description = "Contains the combination of a global input hook and a key-state or foreground-window poll, which is how a software keylogger is built."
        severity = "low"
    strings:
        $hook = "SetWindowsHookEx" ascii
        $k1 = "GetAsyncKeyState" ascii
        $k2 = "GetKeyboardState" ascii
        $k3 = "GetKeyNameText" ascii
        $fg = "GetForegroundWindow" ascii
        $wt = "GetWindowText" ascii
    condition:
        uint16(0) == 0x5A4D and $hook and 1 of ($k*) and 1 of ($fg, $wt)
}

rule irscan_hidden_desktop_marker
{
    meta:
        author = "irscan contributors"
        description = "Names a hidden desktop or hidden-VNC technique explicitly. The names of the Win32 desktop functions are deliberately NOT matched here: CreateDesktopW and SwitchDesktop are imported by winlogon.exe, explorer.exe and every process that touches a window station, so matching them reports Windows itself. Four-letter abbreviations are not matched either: `hvnc` was found inside a base64 certificate blob in NVIDIA Web Helper, where four arbitrary letters are a coincidence rather than a technique. What is worth a lead is a binary that spells the technique out."
        severity = "high"
    strings:
        $h1 = "HiddenDesktop" ascii nocase
        $h2 = "Hidden Desktop" ascii nocase
        $h3 = "HiddenVNC" ascii nocase
        $h4 = "hidden vnc" ascii nocase
        $h5 = "HiddenVnc" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 1 of them
}

rule irscan_remote_control_product_marker
{
    meta:
        author = "irscan contributors"
        description = "Mentions a remote-control or monitoring product by name. Weak on its own - a file that mentions AnyDesk is usually AnyDesk - but it names the product when the file has no signature to do it."
        severity = "low"
    strings:
        $p1 = "AnyDesk" ascii
        $p2 = "TeamViewer" ascii
        $p3 = "RustDesk" ascii
        $p4 = "ScreenConnect" ascii
        $p5 = "Ammyy" ascii
        $p6 = "Remote Utilities" ascii
        $p7 = "LiteManager" ascii
        $p8 = "Supremo" ascii
        $p9 = "AeroAdmin" ascii
        $p10 = "Radmin" ascii
        $p11 = "Kickidler" ascii
        $p12 = "StaffCop" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule irscan_security_software_tamper_marker
{
    meta:
        author = "irscan contributors"
        description = "Contains strings that suggest interference with the security product on the machine - disabling real-time protection, adding an exclusion, or terminating the antivirus service."
        severity = "high"
    strings:
        $d1 = "DisableRealtimeMonitoring" ascii
        $d2 = "DisableAntiSpyware" ascii
        $d3 = "Exclusions\\Paths" ascii
        $d4 = "MpPreference" ascii
        $d5 = "Set-MpPreference" ascii
        $d6 = "WinDefend" ascii
        $d7 = "MsMpEng" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
