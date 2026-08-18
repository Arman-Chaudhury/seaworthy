package manifest

import "strings"

// rawDoc is one document of a multi-document YAML stream, with the
// 1-based line its text starts on in the source file.
type rawDoc struct {
	startLine int
	text      string
}

// splitDocs splits src on top-level "---" separator lines, dropping
// documents that contain only blank lines and comments. Splitting
// ourselves (rather than one yaml.Decoder over the stream) is what lets
// one malformed document turn into a parse-error finding while the rest
// of the file still gets audited (SPEC §3).
func splitDocs(src string) []rawDoc {
	lines := strings.Split(src, "\n")
	var docs []rawDoc
	start := 1
	var cur []string
	flush := func() {
		text := strings.Join(cur, "\n")
		if !blankDoc(text) {
			docs = append(docs, rawDoc{startLine: start, text: text})
		}
		cur = nil
	}
	for i, ln := range lines {
		if isSeparator(ln) {
			flush()
			start = i + 2
			continue
		}
		cur = append(cur, ln)
	}
	flush()
	return docs
}

func isSeparator(ln string) bool {
	if !strings.HasPrefix(ln, "---") {
		return false
	}
	rest := strings.TrimSpace(ln[3:])
	return rest == "" || strings.HasPrefix(rest, "#")
}

func blankDoc(text string) bool {
	for _, ln := range strings.Split(text, "\n") {
		t := strings.TrimSpace(ln)
		if t != "" && !strings.HasPrefix(t, "#") {
			return false
		}
	}
	return true
}
