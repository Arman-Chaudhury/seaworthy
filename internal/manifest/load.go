package manifest

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Arman-Chaudhury/seaworthy/internal/audit"
)

// Load reads manifests from paths ("-" means stdin) into one Snapshot.
// Malformed documents become parse-error findings; only I/O failures
// return an error (exit 2 at the CLI).
func Load(paths []string, stdin io.Reader) (*Snapshot, []audit.Finding, error) {
	var objs []*Object
	var findings []audit.Finding
	for _, p := range paths {
		if p == "-" {
			data, err := io.ReadAll(stdin)
			if err != nil {
				return nil, nil, fmt.Errorf("reading stdin: %w", err)
			}
			o, f := parseFile("<stdin>", string(data))
			objs = append(objs, o...)
			findings = append(findings, f...)
			continue
		}
		files, err := expand(p)
		if err != nil {
			return nil, nil, err
		}
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				return nil, nil, err
			}
			o, f := parseFile(file, string(data))
			objs = append(objs, o...)
			findings = append(findings, f...)
		}
	}
	return NewSnapshot(objs), findings, nil
}

func parseFile(name, content string) ([]*Object, []audit.Finding) {
	var objs []*Object
	var findings []audit.Finding
	for _, doc := range splitDocs(content) {
		obj, f := decodeDoc(doc, name)
		if f != nil {
			findings = append(findings, *f)
			continue
		}
		objs = append(objs, obj)
	}
	return objs, findings
}

// expand resolves a path to the sorted *.yaml/*.yml files under it
// (recursing into directories, skipping dot-directories).
func expand(p string) ([]string, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return []string{p}, nil
	}
	var files []string
	err = filepath.WalkDir(p, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && path != p {
				return fs.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(path); ext == ".yaml" || ext == ".yml" {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}
