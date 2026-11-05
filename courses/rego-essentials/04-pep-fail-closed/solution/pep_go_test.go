package pep

// Regression self-test for the Go PEP (Check QA probes, 2026-11-05). Run: go test ./...

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStrictDecoder(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		delay  time.Duration
		want   bool
	}{
		{"bool_true", 200, `{"result": true}`, 0, true},
		{"bool_false", 200, `{"result": false}`, 0, false},
		{"missing_result", 200, `{}`, 0, false},
		{"null_result", 200, `{"result": null}`, 0, false},
		{"string_true", 200, `{"result": "true"}`, 0, false},
		{"number_one", 200, `{"result": 1}`, 0, false},
		{"obj_allow_string_false", 200, `{"result": {"allow": "false"}}`, 0, false},
		{"obj_allow_true", 200, `{"result": {"allow": true}}`, 0, false},
		{"top_level_list", 200, `[]`, 0, false},
		{"top_level_null", 200, `null`, 0, false},
		{"malformed_json", 200, `{"result": tru`, 0, false},
		{"http_500", 500, `{"result": true}`, 0, false},
		{"trailing_garbage", 200, `{"result": true} garbage`, 0, false},
		{"second_document", 200, `{"result": true}{"result": false}`, 0, false},
		{"list_result", 200, `{"result": [true]}`, 0, false},
		{"http_201_true", 201, `{"result": true}`, 0, false},
		{"http_204_empty", 204, ``, 0, false},
		{"key_Result_case", 200, `{"Result": true}`, 0, false},
		{"key_RESULT_case", 200, `{"RESULT": true}`, 0, false},
		{"timeout", 200, `{"result": true}`, 600 * time.Millisecond, false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(c.delay)
				w.WriteHeader(c.status)
				w.Write([]byte(c.body))
			}))
			defer srv.Close()
			got := AskPDP(srv.URL, "probe", map[string]any{"action": "read"}, 300*time.Millisecond, true)
			if got.Allow != c.want {
				t.Fatalf("allow=%v want %v (%s)", got.Allow, c.want, got.Reason)
			}
		})
	}
	if d := AskPDP("http://127.0.0.1:1", "x", nil, 300*time.Millisecond, true); d.Allow {
		t.Fatal("dead port must deny")
	}
}
