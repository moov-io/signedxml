package signedxml_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moov-io/signedxml"
)

func FuzzValidator(f *testing.F) {
	populateCorpus(f)

	f.Fuzz(func(t *testing.T, contents string) {
		if len(contents) > 1<<20 {
			t.Skip()
		}

		v, err := signedxml.NewValidator(contents)
		if err != nil || v == nil {
			return
		}
		_, _ = v.ValidateReferences()
		_ = v.SigningCert()
	})
}

func populateCorpus(f *testing.F) {
	f.Helper()

	f.Add("")
	f.Add("<root></root>")
	f.Add("<?xml version=\"1.0\"?><foo/>")

	roots := []string{"testdata", filepath.Join("tests", "testdata"), "examples"}
	for _, root := range roots {
		_ = filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			if strings.HasSuffix(strings.ToLower(path), ".xml") {
				bs, err := os.ReadFile(path)
				if err != nil || len(bs) > 512*1024 {
					return nil
				}
				f.Add(string(bs))
			}
			return nil
		})
	}
}
