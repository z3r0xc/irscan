IRScan - portable endpoint triage
=================================

What this is
------------
IRScan looks for hidden employee-monitoring agents, remote-access tools and
spyware on a Windows machine. You copy this folder onto the suspect machine,
run irscan.exe, and read the report it produces.

It is READ-ONLY. It changes nothing. It does not modify, delete, disable or
quarantine anything, it does not install anything, and it does not contact the
network. Its only output is one report file.


Administrator is required
-------------------------
Windows will ask you for permission when you start the tool. That prompt is
required, not optional - the tool will not run without it.

The reason is that Windows hides the most important evidence from ordinary
users. Without Administrator rights the tool cannot read the Security event
log, cannot read Prefetch data, and cannot see the name of certain running
processes. Those are exactly the places a hidden monitoring agent leaves
traces. An unelevated scan would still produce a report, but a clean result
from it would mean much less. So the tool refuses to run that way.


How to run it
-------------
Option 1 - double-click irscan.exe in this folder. Approve the Windows
permission prompt.

Option 2 - from a terminal, in this folder:

    irscan.exe

The scan takes a few minutes. Useful variations:

    irscan.exe --quick          faster, skips the slow checks
    irscan.exe --out D:\folder  write the report to a chosen folder

Run irscan.exe --help for the full list.

Nothing is installed and nothing is left behind in the registry. You can
delete this whole folder afterwards and the machine is back where it started.


Where the report goes
---------------------
By default the report is written to the folder you ran the tool from (usually
this one), named irscan-<computername>-<date>.txt (for example irscan-OFFICE-PC-2026-09-12_19-24-55.txt). If you used --out,
it is in that folder instead. The console shows the exact path when the scan
finishes.

Read the report, but treat the FILE as the record. The console window can be
closed or lost; the file is what you keep.


Copy the report off the machine FIRST
-------------------------------------
Before you clean up anything on the suspect machine - before uninstalling,
changing, or restarting anything - copy the report file onto a USB stick or
another machine.

The report is evidence. Once you change the machine, that evidence is gone and
cannot be recovered. If you must re-run the tool later, you will get a
different report from a machine that no longer looks the way it did.


A clean result is not proof
---------------------------
If the report says nothing was found, that does NOT prove the machine is clean.

Some tools hide from a scan like this. The machine may have been compromised in
a way this tool does not cover, the malicious software may not have been
running at the time, or the evidence may already have been deleted by whoever
installed it. A clean report means "nothing in this tool's checks fired" - not
"this machine is trustworthy".

If you have a real suspicion, do not treat a clean report as the end of the
investigation. Get a specialist to look at the machine.


Files in this folder
--------------------
irscan.exe          the tool
README.txt          this file
SHA256SUMS.txt      list of file fingerprints, used to prove nothing changed
verify-hashes.ps1   checks the files above against SHA256SUMS.txt
