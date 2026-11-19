package agent

// Regression (M-01): the updater used to install a binary whenever the checksum
// manifest was missing (fail-open). It must refuse unless explicitly opted out.
