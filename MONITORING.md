# Monitoring

Start a new process to load code updates; an already running capture keeps its old code.

The lower panel lists observed transmitter MAC addresses (not unique physical devices;
randomized addresses can represent the same device). PgUp/PgDn scrolls this panel.
AUTH, association, reassociation, deauthentication, disassociation, EAPOL and M1–M4
counts include retransmissions and refer to packets sent by that MAC, not complete exchanges.

Background tshark statistics refresh roughly every 30 seconds plus processing time.
Closed files are summarized once; the active file is reread. Large active files can
make updates slower. Frames buffered by dumpcap do not appear until flushed.
A failed analysis leaves the previous statistics visible with a stale warning.

Every roughly 120 seconds, hcxpcapngtool checks the session files together, allowing
exchanges spanning rotations. Green means a converter-accepted WPA record exists
for an AP/client pair containing this MAC. It does not imply all four messages were
captured, that every association is complete, or that password recovery will succeed.
Use offline Analysis after stopping for final results and explicit exports.

New sessions stage files in /var/tmp/.recording-* outside the private home directory, avoiding private-directory access failures; moves are cheap when both locations share a filesystem. On normal stop files move to
captures. After a crash the hidden directory remains: preserve it and inspect the
files before manually moving them to captures. No automatic crash recovery is implemented.
The screen reports disk space; there is no automatic low-space stop or retention policy.
No running captures are restarted by code edits.

Each device uses two display rows: identity and average RSSI, then packet/auth counts.
Names use advertised WPS Device Name when available, otherwise the SSID advertised
in beacons/probe responses (explicitly labeled SSID). Probe-request SSIDs are not
used as device names. Missing names and RSSI are shown explicitly.
RSSI is the arithmetic mean in dBm of available per-frame first-antenna readings,
weighted by the number of samples across all files in the current session.
It is not a distance estimate or a recent-window signal measurement.

## Exit confirmation and hashcat

Ctrl+C (SIGINT) asks before stopping, with No selected by default. Escape or another
Ctrl+C cancels the dialog. Selecting Yes stops the capture and hashcat child process
and preserves capture files and already recovered results. SIGKILL/power loss cannot
be intercepted. This is a safeguard for terminal/layout shortcuts; copying itself is
handled by the terminal. Pending offline analysis may finish before exit cleanup.

Hashcat menu: select an exported data/ready dataset, choose a dictionary from wordlists/
or enter its full path, then Start. Dictionaries are plain text, one candidate per line.
The implementation uses mode 22000, dictionary attack and workload 1. The Dictionaries
menu downloads a curated, pinned SecLists catalog (see WORDLISTS.md). It does not launch
brute force or run against cached evidence. Each input is checked against its export
manifest and copied into a unique job folder.

Results: data/hashcat/<run>/recovered.txt (hash and plaintext), private hashcat.potfile,
source-manifest.json, input.22000, hashcat.restore and run.json. Logs:
log/hashcat-<run>.log; each resume has a separate log. Preparation/workflow failures
also get log/hashcat-error-<timestamp>-<id>.log when the disk permits logging.
Before launching, the app creates the result directory, performs a real write/fsync/delete
probe, opens result/potfile/log files, and atomically saves metadata. Files are private.
New recovered results are synced when observed; run.json is atomically replaced every
10 seconds while running and immediately when results arrive or the process stops.
This reduces data loss risk but cannot guarantee survival of every write during a
power failure or broken storage hardware.

The live screen displays hashcat JSON progress, rejected candidates, recovered hashes,
H/s, ETA, actual active device names/types and available temperature/utilization/fan
telemetry. Missing telemetry is marked unavailable. Progress is hashcat work units,
which can include rejected candidates and multiple salts; it is not necessarily the
number of unique dictionary lines. Startup/compilation can precede the first status.

History offers results and Resume. Native hashcat checkpoints are independent of the
10-second UI snapshots: resume may repeat work since the last engine checkpoint.
Input and dictionary SHA-256 must still match; do not move/change them. The lock held
by both app and child prevents two instances from resuming the same task. A running
label left by a crash can be stale; the lock and checkpoint determine resumability.
If no checkpoint was produced, restart as a new job. Completed/exhausted jobs normally
have no checkpoint. Resume supports traditional --restore and newer --restore-position.

Hashcat reports cryptographic matches against the recorded WPA data, not speculative
password scores. Matches are shown and saved immediately. For multiple hashes it
continues until all are recovered or the dictionary is exhausted. A match does not
establish that the router still has the same password. Candidate guesses are not
saved as recovered passwords. C/Q/Escape asks before saving and stopping; Ctrl+C uses the shared
exit confirmation. Keep the complete job directory to preserve both results and resume.


### Промени след review от 30.10.2026

При Stop фоновите tshark/hcx процеси се прекратяват и прибират преди местенето. Скоростта на запис се показва в MiB/s; изгубените пакети са „н/д“, когато dumpcap не предоставя брояч. Готовността е „наблюдавано в сесията“, с възраст на проверката, а не текуща свързаност.

Capture staging вече има `session.json`. Прибирането публикува проверени копия без презаписване; след отказ се повтарят само незавършените операции. Следващ старт предлага възстановяване на сесиите с журнал и спрян процес. Папки от старата версия без журнал не се прибират автоматично.

K отваря архива, A архивира избраното; в архива A връща обратно. Архивираните файлове са извън автоматичната проверка за готовност. [Извлечени] следва съдържанието, включително когато готовият набор е архивиран.
