package opnsenseunbound

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/libdns/libdns"
)

func TestTrimZone(t *testing.T) {
	tests := []struct {
		name     string
		zone     string
		expected string
	}{
		{"with trailing dot", "example.com.", "example.com"},
		{"without trailing dot", "example.com", "example.com"},
		{"empty string", "", ""},
		{"only dot", ".", ""},
		{"multiple dots", "sub.example.com.", "sub.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := trimZone(tt.zone)
			if result != tt.expected {
				t.Errorf("trimZone(%q) = %q, want %q", tt.zone, result, tt.expected)
			}
		})
	}
}

func TestResolveHostAndDomain(t *testing.T) {
	tests := []struct {
		name             string
		recordName       string
		zone             string
		expectedHostname string
		expectedDomain   string
	}{
		{"normal subdomain", "www", "example.com", "www", "example.com"},
		{"zone apex with @", "@", "example.com", "example", "com"},
		{"zone apex empty", "", "example.com", "example", "com"},
		{"subdomain with trailing dot zone", "api", "example.com.", "api", "example.com"},
		{"apex with trailing dot zone", "@", "my_domain.org.", "my_domain", "org"},
		{"single label zone apex", "@", "localhost", "localhost", ""},
		{"deep subdomain", "deep.sub", "example.com", "deep.sub", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostname, domain := resolveHostAndDomain(tt.recordName, tt.zone)
			if hostname != tt.expectedHostname || domain != tt.expectedDomain {
				t.Errorf("resolveHostAndDomain(%q, %q) = (%q, %q), want (%q, %q)",
					tt.recordName, tt.zone, hostname, domain, tt.expectedHostname, tt.expectedDomain)
			}
		})
	}
}

func TestIsWildcard(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"single asterisk", "*", true},
		{"wildcard prefix", "*.example", true},
		{"normal name", "www", false},
		{"asterisk in middle", "te*st", false},
		{"asterisk at end", "test*", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isWildcard(tt.input)
			if result != tt.expected {
				t.Errorf("isWildcard(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetDescription(t *testing.T) {
	tests := []struct {
		name        string
		description string
		expected    string
	}{
		{"custom description", "My Custom Desc", "My Custom Desc"},
		{"empty description", "", "Managed by Caddy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{Description: tt.description}
			result := p.getDescription()
			if result != tt.expected {
				t.Errorf("getDescription() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestBaseURL(t *testing.T) {
	p := &Provider{Host: "opnsense.local"}
	expected := "https://opnsense.local/api/unbound"
	result := p.baseURL()
	if result != expected {
		t.Errorf("baseURL() = %q, want %q", result, expected)
	}
}

func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(handler)
}

func newTestProvider(t *testing.T, serverURL string) *Provider {
	t.Helper()
	// Extract host from URL (remove https://)
	host := strings.TrimPrefix(serverURL, "https://")
	p := &Provider{
		Host:      host,
		APIKey:    "test-key",
		APISecret: "test-secret",
		Insecure:  true,
	}
	return p
}

func TestGetRecords(t *testing.T) {
	tests := []struct {
		name           string
		zone           string
		serverResponse searchHostOverrideResponse
		expectedCount  int
		expectedNames  []string
	}{
		{
			name: "returns matching records",
			zone: "example.com",
			serverResponse: searchHostOverrideResponse{
				Rows: []unboundHostOverride{
					{UUID: "1", Hostname: "www", Domain: "example.com", Server: "192.168.1.1", RR: "A", Enabled: "1"},
					{UUID: "2", Hostname: "api", Domain: "example.com", Server: "192.168.1.2", RR: "A", Enabled: "1"},
					{UUID: "3", Hostname: "other", Domain: "otherdomain.com", Server: "192.168.1.3", RR: "A", Enabled: "1"},
				},
			},
			expectedCount: 2,
			expectedNames: []string{"www", "api"},
		},
		{
			name: "returns apex record",
			zone: "my_domain.com",
			serverResponse: searchHostOverrideResponse{
				Rows: []unboundHostOverride{
					{UUID: "1", Hostname: "my_domain", Domain: "com", Server: "192.168.1.1", RR: "A", Enabled: "1"},
				},
			},
			expectedCount: 1,
			expectedNames: []string{"@"},
		},
		{
			name: "returns IPv6 records",
			zone: "example.com",
			serverResponse: searchHostOverrideResponse{
				Rows: []unboundHostOverride{
					{UUID: "1", Hostname: "www", Domain: "example.com", Server: "2001:db8::1", RR: "AAAA", Enabled: "1"},
				},
			},
			expectedCount: 1,
			expectedNames: []string{"www"},
		},
		{
			name: "filters non-A/AAAA records",
			zone: "example.com",
			serverResponse: searchHostOverrideResponse{
				Rows: []unboundHostOverride{
					{UUID: "1", Hostname: "www", Domain: "example.com", Server: "192.168.1.1", RR: "A", Enabled: "1"},
					{UUID: "2", Hostname: "mail", Domain: "example.com", Server: "mx.example.com", RR: "MX", Enabled: "1"},
				},
			},
			expectedCount: 1,
			expectedNames: []string{"www"},
		},
		{
			name: "empty response",
			zone: "example.com",
			serverResponse: searchHostOverrideResponse{
				Rows: []unboundHostOverride{},
			},
			expectedCount: 0,
			expectedNames: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/unbound/settings/search_host_override" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				// Unbound uses POST for search
				if r.Method != http.MethodPost {
					t.Errorf("unexpected method: %s", r.Method)
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tt.serverResponse)
			})
			defer server.Close()

			p := newTestProvider(t, server.URL)
			records, err := p.GetRecords(context.Background(), tt.zone)
			if err != nil {
				t.Fatalf("GetRecords() error = %v", err)
			}

			if len(records) != tt.expectedCount {
				t.Errorf("GetRecords() returned %d records, want %d", len(records), tt.expectedCount)
			}

			for i, expectedName := range tt.expectedNames {
				if i >= len(records) {
					break
				}
				rr := records[i].RR()
				if rr.Name != expectedName {
					t.Errorf("record[%d].Name = %q, want %q", i, rr.Name, expectedName)
				}
			}
		})
	}
}

func TestAppendRecords(t *testing.T) {
	tests := []struct {
		name          string
		zone          string
		records       []libdns.Record
		expectError   bool
		expectedAdded int
	}{
		{
			name: "append A record",
			zone: "example.com",
			records: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.1")},
			},
			expectError:   false,
			expectedAdded: 1,
		},
		{
			name: "append AAAA record",
			zone: "example.com",
			records: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("2001:db8::1")},
			},
			expectError:   false,
			expectedAdded: 1,
		},
		{
			name: "append multiple records",
			zone: "example.com",
			records: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.1")},
				libdns.Address{Name: "api", IP: mustParseAddr("192.168.1.2")},
			},
			expectError:   false,
			expectedAdded: 2,
		},
		{
			name: "reject unsupported record type",
			zone: "example.com",
			records: []libdns.Record{
				libdns.TXT{Name: "txt", Text: "some text"},
			},
			expectError:   true,
			expectedAdded: 0,
		},
		{
			name: "skip wildcard record",
			zone: "example.com",
			records: []libdns.Record{
				libdns.Address{Name: "*", IP: mustParseAddr("192.168.1.1")},
			},
			expectError:   false,
			expectedAdded: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addCount := 0
			reconfigured := false

			server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")

				if strings.HasPrefix(r.URL.Path, "/api/unbound/settings/add_host_override") {
					addCount++
					json.NewEncoder(w).Encode(apiResponse{Result: "saved"})
					return
				}
				if r.URL.Path == "/api/unbound/service/reconfigure" {
					reconfigured = true
					json.NewEncoder(w).Encode(apiResponse{Status: "ok"})
					return
				}
				t.Errorf("unexpected path: %s", r.URL.Path)
			})
			defer server.Close()

			p := newTestProvider(t, server.URL)
			added, err := p.AppendRecords(context.Background(), tt.zone, tt.records)

			if tt.expectError {
				if err == nil {
					t.Error("AppendRecords() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("AppendRecords() error = %v", err)
			}

			if len(added) != tt.expectedAdded {
				t.Errorf("AppendRecords() added %d records, want %d", len(added), tt.expectedAdded)
			}

			if addCount != tt.expectedAdded {
				t.Errorf("add_host_override called %d times, want %d", addCount, tt.expectedAdded)
			}

			if tt.expectedAdded > 0 && !reconfigured {
				t.Error("reconfigure was not called")
			}
		})
	}
}

func TestDeleteRecords(t *testing.T) {
	tests := []struct {
		name            string
		zone            string
		existingHosts   []unboundHostOverride
		recordsToDelete []libdns.Record
		expectedDeleted int
	}{
		{
			name: "delete existing record",
			zone: "example.com",
			existingHosts: []unboundHostOverride{
				{UUID: "uuid-1", Hostname: "www", Domain: "example.com", Server: "192.168.1.1", RR: "A", Enabled: "1"},
			},
			recordsToDelete: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.1")},
			},
			expectedDeleted: 1,
		},
		{
			name: "delete non-existing record",
			zone: "example.com",
			existingHosts: []unboundHostOverride{
				{UUID: "uuid-1", Hostname: "www", Domain: "example.com", Server: "192.168.1.1", RR: "A", Enabled: "1"},
			},
			recordsToDelete: []libdns.Record{
				libdns.Address{Name: "api", IP: mustParseAddr("192.168.1.2")},
			},
			expectedDeleted: 0,
		},
		{
			name: "delete apex record",
			zone: "my_domain.com",
			existingHosts: []unboundHostOverride{
				{UUID: "uuid-1", Hostname: "my_domain", Domain: "com", Server: "192.168.1.1", RR: "A", Enabled: "1"},
			},
			recordsToDelete: []libdns.Record{
				libdns.Address{Name: "@", IP: mustParseAddr("192.168.1.1")},
			},
			expectedDeleted: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deleteCount := 0
			reconfigured := false

			server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")

				if r.URL.Path == "/api/unbound/settings/search_host_override" {
					json.NewEncoder(w).Encode(searchHostOverrideResponse{Rows: tt.existingHosts})
					return
				}
				if strings.HasPrefix(r.URL.Path, "/api/unbound/settings/del_host_override/") {
					deleteCount++
					json.NewEncoder(w).Encode(apiResponse{Result: "deleted"})
					return
				}
				if r.URL.Path == "/api/unbound/service/reconfigure" {
					reconfigured = true
					json.NewEncoder(w).Encode(apiResponse{Status: "ok"})
					return
				}
				t.Errorf("unexpected path: %s", r.URL.Path)
			})
			defer server.Close()

			p := newTestProvider(t, server.URL)
			deleted, err := p.DeleteRecords(context.Background(), tt.zone, tt.recordsToDelete)
			if err != nil {
				t.Fatalf("DeleteRecords() error = %v", err)
			}

			if len(deleted) != tt.expectedDeleted {
				t.Errorf("DeleteRecords() deleted %d records, want %d", len(deleted), tt.expectedDeleted)
			}

			if deleteCount != tt.expectedDeleted {
				t.Errorf("del_host_override called %d times, want %d", deleteCount, tt.expectedDeleted)
			}

			if tt.expectedDeleted > 0 && !reconfigured {
				t.Error("reconfigure was not called")
			}
		})
	}
}

func TestSetRecords(t *testing.T) {
	tests := []struct {
		name          string
		zone          string
		existingHosts []unboundHostOverride
		recordsToSet  []libdns.Record
		expectAdd     int
		expectDelete  int
	}{
		{
			name:          "create new record",
			zone:          "example.com",
			existingHosts: []unboundHostOverride{},
			recordsToSet: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.1")},
			},
			expectAdd:    1,
			expectDelete: 0,
		},
		{
			name: "update existing record",
			zone: "example.com",
			existingHosts: []unboundHostOverride{
				{UUID: "uuid-1", Hostname: "www", Domain: "example.com", Server: "192.168.1.1", RR: "A", Enabled: "1", Description: "Managed by Caddy"},
			},
			recordsToSet: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.2")},
			},
			expectAdd:    1,
			expectDelete: 1,
		},
		{
			name: "skip identical record",
			zone: "example.com",
			existingHosts: []unboundHostOverride{
				{UUID: "uuid-1", Hostname: "www", Domain: "example.com", Server: "192.168.1.1", RR: "A", Enabled: "1", Description: "Managed by Caddy"},
			},
			recordsToSet: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.1")},
			},
			expectAdd:    0,
			expectDelete: 0,
		},
		{
			name: "skip wildcard record",
			zone: "example.com",
			existingHosts: []unboundHostOverride{},
			recordsToSet: []libdns.Record{
				libdns.Address{Name: "*.sub", IP: mustParseAddr("192.168.1.1")},
			},
			expectAdd:    0,
			expectDelete: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addCount := 0
			deleteCount := 0
			reconfigured := false

			server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")

				if r.URL.Path == "/api/unbound/settings/search_host_override" {
					json.NewEncoder(w).Encode(searchHostOverrideResponse{Rows: tt.existingHosts})
					return
				}
				if strings.HasPrefix(r.URL.Path, "/api/unbound/settings/add_host_override") {
					addCount++
					json.NewEncoder(w).Encode(apiResponse{Result: "saved"})
					return
				}
				if strings.HasPrefix(r.URL.Path, "/api/unbound/settings/del_host_override/") {
					deleteCount++
					json.NewEncoder(w).Encode(apiResponse{Result: "deleted"})
					return
				}
				if r.URL.Path == "/api/unbound/service/reconfigure" {
					reconfigured = true
					json.NewEncoder(w).Encode(apiResponse{Status: "ok"})
					return
				}
				t.Errorf("unexpected path: %s", r.URL.Path)
			})
			defer server.Close()

			p := newTestProvider(t, server.URL)
			_, err := p.SetRecords(context.Background(), tt.zone, tt.recordsToSet)
			if err != nil {
				t.Fatalf("SetRecords() error = %v", err)
			}

			if addCount != tt.expectAdd {
				t.Errorf("add_host_override called %d times, want %d", addCount, tt.expectAdd)
			}

			if deleteCount != tt.expectDelete {
				t.Errorf("del_host_override called %d times, want %d", deleteCount, tt.expectDelete)
			}

			needsReconfigure := tt.expectAdd > 0 || tt.expectDelete > 0
			if needsReconfigure && !reconfigured {
				t.Error("reconfigure was not called")
			}
			if !needsReconfigure && reconfigured {
				t.Error("reconfigure was called unexpectedly")
			}
		})
	}
}

func TestAPIErrorHandling(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
	}{
		{"server error", http.StatusInternalServerError, "Internal Server Error"},
		{"unauthorized", http.StatusUnauthorized, "Unauthorized"},
		{"not found", http.StatusNotFound, "Not Found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			})
			defer server.Close()

			p := newTestProvider(t, server.URL)
			_, err := p.GetRecords(context.Background(), "example.com")

			if err == nil {
				t.Error("expected error, got nil")
			}

			if !strings.Contains(err.Error(), "API error") {
				t.Errorf("error should contain 'API error', got: %v", err)
			}
		})
	}
}

// Helper function for tests
func mustParseAddr(s string) (addr netip.Addr) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr
}
