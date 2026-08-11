// Package web serves the embedded Command Hub interface.
//
// The whole UI — markup, styles and script — is compiled into the binary, so
// deploying the hub means copying one file. There are no CDN references and no
// build step, which is also what lets the Content-Security-Policy stay at
// 'self' for every directive.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed static
var content embed.FS

// Handler serves the UI, falling back to the single-page shell for unknown
// paths so client-side routing works on a hard refresh.
func Handler() http.Handler {
	sub, err := fs.Sub(content, "static")
	if err != nil {
		panic("embedded UI is missing: " + err.Error())
	}
	files := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(sub, path); err != nil {
			// Unknown path: hand back the shell rather than a 404, so a
			// bookmarked view still loads.
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		// Assets are content-hashed by release, not by name, so a short cache
		// keeps a redeploy from serving a stale script for hours.
		if strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".js") {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}
