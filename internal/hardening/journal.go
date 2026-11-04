// journal.go — apply journals. Every apply writes one journal (the record
// of what changed and how to undo it) plus a generated rollback script that
// works even when the agent binary is dead or being upgraded. Files:
//
//	<StateDir>/journal.json              latest journal (pointer)
//	<StateDir>/journal-<id>.json         journal by id
//	<StateDir>/journal-<id>.json.rolledback | .confirmed   terminal states
//	<StateDir>/rollback-<id>.sh          generated rollback script (0700)
//	<StateDir>/rollback-<id>.log         script output

package hardening

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Step is one executed plan item and how to undo it.
type Step struct {
	Item    PlanItem   `json:"item"`
	Cmds    [][]string `json:"cmds,omitempty"`    // executed argvs
	Undo    [][]string `json:"undo,omitempty"`    // inverse argvs (reverse order on rollback)
	Files   []FileUndo `json:"files,omitempty"`   // file writes this step did
	Skipped bool       `json:"skipped,omitempty"` // no-op / blocked
	Note    string     `json:"note,omitempty"`
}

// FileUndo restores one owned file to its previous bytes (absent before =
// remove on undo).
type FileUndo struct {
	Path   string `json:"path"`
	Before string `json:"before,omitempty"` // "" with BeforeAbsent = file did not exist
	Absent bool   `json:"absent,omitempty"`
	Mode   uint32 `json:"mode"`
}

// Journal is the full record of one apply.
type Journal struct {
	ID          string         `json:"id"`
	ProfileName string         `json:"profile_name"`
	StartedAt   int64          `json:"started_at"`
	FinishedAt  int64          `json:"finished_at,omitempty"`
	SafeApply   bool           `json:"safe_apply"`
	Confirmed   bool           `json:"confirmed"`
	RolledBack  bool           `json:"rolled_back"`
	TimerUnit   string         `json:"timer_unit,omitempty"`
	TimeoutSec  int            `json:"timeout_sec,omitempty"`
	Before      *DetectedState `json:"before,omitempty"`
	Steps       []Step         `json:"steps"`
	Error       string         `json:"error,omitempty"`
}

// ---- paths ----

func journalPath(id string) string        { return filepath.Join(StateDir, "journal-"+id+".json") }
func latestJournalPath() string           { return filepath.Join(StateDir, "journal.json") }
func rollbackScriptPath(id string) string { return filepath.Join(StateDir, "rollback-"+id+".sh") }
func rollbackLogPath(id string) string    { return filepath.Join(StateDir, "rollback-"+id+".log") }

// saveJournal atomically persists a journal under both its id and the
// latest pointer.
func saveJournal(j *Journal) error {
	if err := os.MkdirAll(StateDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(journalPath(j.ID), string(b), 0o600); err != nil {
		return err
	}
	return writeFileAtomic(latestJournalPath(), string(b), 0o600)
}

// markJournalTerminal renames the journal files to the terminal state and
// drops the latest pointer if it still names this journal.
func markJournalTerminal(j *Journal, suffix string) {
	_ = os.Rename(journalPath(j.ID), journalPath(j.ID)+suffix)
	if lj, err := LoadLatestJournal(); err == nil && lj != nil && lj.ID == j.ID {
		_ = os.Remove(latestJournalPath())
	}
}

// LoadLatestJournal reads the latest journal, preferring the newest
// non-terminal one, then the most recent terminal one (status reporting).
func LoadLatestJournal() (*Journal, error) {
	entries, err := os.ReadDir(StateDir)
	if err != nil {
		return nil, err
	}
	type cand struct {
		path string
		mod  int64
	}
	var live, done []cand
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "journal-") || !strings.HasSuffix(name, ".json") || name == "journal.json" {
			continue
		}
		full := filepath.Join(StateDir, name)
		info, err := e.Info()
		if err != nil {
			continue
		}
		if strings.HasSuffix(name, ".json.rolledback") || strings.HasSuffix(name, ".json.confirmed") || strings.HasSuffix(name, ".json.failed") {
			done = append(done, cand{full, info.ModTime().UnixNano()})
			continue
		}
		live = append(live, cand{full, info.ModTime().UnixNano()})
	}
	src := live
	if len(src) == 0 {
		src = done
		if len(src) == 0 {
			// Fall back to the latest pointer for pre-rename journals.
			b, err := readFile(latestJournalPath())
			if err != nil {
				return nil, err
			}
			var j Journal
			if err := json.Unmarshal(b, &j); err != nil {
				return nil, err
			}
			return &j, nil
		}
	}
	sort.Slice(src, func(i, k int) bool { return src[i].mod > src[k].mod })
	b, err := readFile(src[0].path)
	if err != nil {
		return nil, err
	}
	var j Journal
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

// LoadJournal reads one journal by id.
func LoadJournal(id string) (*Journal, error) {
	b, err := readFile(journalPath(id))
	if err != nil {
		return nil, err
	}
	var j Journal
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	return &j, nil
}
