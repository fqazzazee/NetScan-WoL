package web

import (
	"regexp"
	"strings"
	"testing"
)

// readAsset pulls one embedded file out of the UI bundle.
func readAsset(t *testing.T, name string) string {
	t.Helper()
	data, err := content.ReadFile("static/" + name)
	if err != nil {
		t.Fatalf("read embedded %s: %v", name, err)
	}
	return string(data)
}

var (
	hiddenElement = regexp.MustCompile(`<[a-zA-Z]+[^>]*\shidden[\s>]`)
	classAttr     = regexp.MustCompile(`class="([^"]*)"`)
)

// TestHiddenAttributeIsEnforced is a regression test for a blank panel sitting
// over the sign-in form.
//
// The interface shows and hides every view, dialog and status line through the
// HTML `hidden` attribute. Browsers implement that with a user-agent rule of
// `[hidden] { display: none }`, and *any* author declaration of `display`
// overrides it, because author styles outrank the user-agent stylesheet.
//
// So `.modal { display: grid }` left the dialog permanently rendered as an
// empty card over the page, and `.login { display: grid }` meant the sign-in
// screen never went away after signing in. Both needed one guard rule.
//
// This test fails if that guard is removed while any styled element still
// relies on `hidden`.
func TestHiddenAttributeIsEnforced(t *testing.T) {
	html := readAsset(t, "index.html")
	css := readAsset(t, "app.css")

	if !hiddenElement.MatchString(html) {
		t.Skip("no element uses the hidden attribute, so the guard is unnecessary")
	}

	guard := regexp.MustCompile(`\[hidden\]\s*\{[^}]*display:\s*none\s*!important`)
	if !guard.MatchString(css) {
		t.Error("app.css has no `[hidden] { display: none !important }` rule.\n" +
			"Without it, any class that sets `display` overrides the hidden attribute " +
			"and the element stays on screen — which is how an empty modal ended up " +
			"covering the sign-in form.")
	}
}

// TestStyledHiddenElementsAreListed reports which hidden elements carry a class
// that sets `display`. These are the ones that break without the guard above,
// so naming them makes the risk visible rather than theoretical.
func TestStyledHiddenElementsAreListed(t *testing.T) {
	html := readAsset(t, "index.html")
	css := readAsset(t, "app.css")

	// Collect classes that declare a display property.
	displayRule := regexp.MustCompile(`\.([a-zA-Z][\w-]*)[^{}]*\{[^}]*display:\s*[a-z-]+`)
	styled := map[string]bool{}
	for _, m := range displayRule.FindAllStringSubmatch(css, -1) {
		styled[m[1]] = true
	}

	var atRisk []string
	for _, tag := range hiddenElement.FindAllString(html, -1) {
		cm := classAttr.FindStringSubmatch(tag)
		if cm == nil {
			continue
		}
		for _, class := range strings.Fields(cm[1]) {
			if styled[class] {
				atRisk = append(atRisk, class)
			}
		}
	}

	if len(atRisk) > 0 {
		t.Logf("hidden elements whose classes also set display (guarded by the [hidden] rule): %s",
			strings.Join(atRisk, ", "))
	}
}

// TestUIAssetsArePresent guards against a build that embeds an empty bundle,
// which would serve a blank page with no error anywhere.
func TestUIAssetsArePresent(t *testing.T) {
	for _, name := range []string{"index.html", "app.css", "app.js"} {
		if body := readAsset(t, name); len(body) < 500 {
			t.Errorf("%s is only %d bytes; the embedded UI looks truncated", name, len(body))
		}
	}
}

// TestNoExternalReferences keeps the Content-Security-Policy honest. The hub
// sends 'self' for every directive, so a stylesheet, script or image pulled
// from another origin would be blocked at runtime and silently break whatever
// depended on it.
//
// Two things that look like external references but are not, and are excluded:
// a `data:` URI carries its content inline, and an `xmlns` value is an XML
// namespace identifier that is never dereferenced.
func TestNoExternalReferences(t *testing.T) {
	fetching := regexp.MustCompile(`(?:src|href)\s*=\s*"(https?://[^"]+)"|url\(\s*['"]?(https?://[^'")]+)`)

	for _, name := range []string{"index.html", "app.css", "app.js"} {
		body := readAsset(t, name)
		for _, m := range fetching.FindAllStringSubmatch(body, -1) {
			ref := m[1]
			if ref == "" {
				ref = m[2]
			}
			t.Errorf("%s fetches %s from another origin, which the CSP blocks", name, ref)
		}

		// An xmlns is fine anywhere; a bare absolute URL in a fetching position
		// is what the regex above catches. Assert the namespace case explicitly
		// so a future reader knows it was considered rather than missed.
		if strings.Contains(body, "xmlns=") && !strings.Contains(body, "data:") {
			t.Logf("%s declares an XML namespace outside a data: URI — worth a look", name)
		}
	}
}
