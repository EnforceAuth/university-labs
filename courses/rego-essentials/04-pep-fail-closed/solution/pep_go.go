// Associate Lab B — minimal PEP stub (Go).
// Build OPA input, optional PIP enrich, call PDP, fail-closed on error.
// Not production code. Stock OPA REST only. Writ not on path. Verdict unused.
package pep

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Decision struct {
	Allow  bool
	Reason string
}

type OwnerLookup func(resourceID string) (owner string, ok bool)

func EnrichOwner(resource map[string]any, lookup OwnerLookup) map[string]any {
	out := map[string]any{}
	for k, v := range resource {
		out[k] = v
	}
	if _, has := out["owner"]; has || lookup == nil {
		return out
	}
	id, _ := out["id"].(string)
	if owner, ok := lookup(id); ok {
		out["owner"] = owner
	}
	return out
}

func AskPDP(opaURL, path string, input map[string]any, timeout time.Duration, failClosed bool) Decision {
	if timeout == 0 {
		timeout = 500 * time.Millisecond
	}
	url := fmt.Sprintf("%s/v1/data/%s", trimSlash(opaURL), trimSlash(path))
	body, _ := json.Marshal(map[string]any{"input": input})
	client := &http.Client{Timeout: timeout}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		if failClosed {
			return Decision{Allow: false, Reason: "pdp_error_fail_closed"}
		}
		return Decision{Allow: true, Reason: "pdp_error_fail_open"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if failClosed {
			return Decision{Allow: false, Reason: "pdp_http_status_fail_closed"}
		}
		return Decision{Allow: true, Reason: "pdp_http_status_fail_open"}
	}
	var payload map[string]any // exact key match: Go struct tags match case-insensitively
	raw, readErr := io.ReadAll(resp.Body)
	if err := json.Unmarshal(raw, &payload); readErr != nil || err != nil {
		if failClosed {
			return Decision{Allow: false, Reason: "pdp_bad_json_fail_closed"}
		}
		return Decision{Allow: true, Reason: "pdp_bad_json_fail_open"}
	}
	switch v := payload["result"].(type) {
	case bool:
		return Decision{Allow: v, Reason: "pdp"}
	}
	if failClosed {
		return Decision{Allow: false, Reason: "pdp_bad_shape_fail_closed"}
	}
	return Decision{Allow: true, Reason: "pdp_bad_shape_fail_open"}
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	for len(s) > 0 && s[0] == '/' {
		s = s[1:]
	}
	return s
}
