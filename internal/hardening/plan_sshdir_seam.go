package hardening

import "os"

// sshdDropInDir is the directory the owned sshd drop-in lives in. A seam
// (tests point it at the fake host root) for the earlier-drop-in
// conflict scan (RUNBOOK-FIXES item 10).
var sshDropInDir = "/etc/ssh/sshd_config.d"

// dirList lists one directory. A seam so tests can serve the fake host's
// sshd_config.d without touching the real filesystem.
var dirList = func(dir string) ([]os.DirEntry, error) {
	return os.ReadDir(dir)
}
