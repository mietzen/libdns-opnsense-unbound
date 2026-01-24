// Package opnsenseunbound implements a DNS record management client compatible
// with the libdns interfaces for OPNsense Unbound host overrides.
//
// This provider manages local DNS host entries via the OPNsense API.
// Only A and AAAA records are supported (no TXT records, so ACME DNS challenges
// cannot be performed with this provider).
package opnsenseunbound

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

// DefaultCleanupDelay is the default delay before orphan cleanup runs
const DefaultCleanupDelay = 5 * time.Second

// Provider facilitates DNS record manipulation with OPNsense Unbound.
type Provider struct {
	// Host is the OPNsense hostname or IP address (e.g., "opnsense.example.com" or "192.168.1.1")
	Host string `json:"host,omitempty"`
	// APIKey is the OPNsense API key
	APIKey string `json:"api_key,omitempty"`
	// APISecret is the OPNsense API secret
	APISecret string `json:"api_secret,omitempty"`
	// Insecure skips TLS certificate verification (for self-signed certificates)
	Insecure bool `json:"insecure,omitempty"`
	// Description is set on created host entries (defaults to "Managed by Caddy")
	Description string `json:"description,omitempty"`
	// CleanupDelay is the delay after last SetRecords before orphan cleanup runs (default 5s)
	CleanupDelay time.Duration `json:"cleanup_delay,omitempty"`
	// Logger is an optional logger. If set, warnings will be logged using this logger.
	// When used with Caddy, set this to ctx.Logger() during Provision to match Caddy's log format.
	Logger *zap.Logger `json:"-"`

	client     *http.Client
	clientOnce sync.Once

	// Sync tracking for orphan cleanup
	syncMu         sync.Mutex
	syncTimer      *time.Timer
	managedRecords map[string]struct{} // key: "hostname:domain"
	syncZones      map[string]struct{} // zones touched this session
}

// unboundHostOverride represents a host override entry from the OPNsense Unbound API
type unboundHostOverride struct {
	UUID        string `json:"uuid"`
	Enabled     string `json:"enabled"`
	Hostname    string `json:"hostname"`
	Domain      string `json:"domain"`
	RR          string `json:"rr"`
	MXPrio      string `json:"mxprio"`
	MX          string `json:"mx"`
	Server      string `json:"server"`
	Description string `json:"description"`
}

// searchHostOverrideResponse is the response from settings/search_host_override
type searchHostOverrideResponse struct {
	Rows []unboundHostOverride `json:"rows"`
}

// addHostOverrideRequest is the request body for settings/add_host_override
type addHostOverrideRequest struct {
	Host addHostOverrideData `json:"host"`
}

type addHostOverrideData struct {
	Enabled     string `json:"enabled"`
	Hostname    string `json:"hostname"`
	Domain      string `json:"domain"`
	RR          string `json:"rr"`
	MXPrio      string `json:"mxprio"`
	MX          string `json:"mx"`
	Server      string `json:"server"`
	Description string `json:"description"`
}

// apiResponse is a generic API response
type apiResponse struct {
	Result  string `json:"result,omitempty"`
	Status  string `json:"status,omitempty"`
	Message string `json:"message,omitempty"`
}

func (p *Provider) getClient() *http.Client {
	p.clientOnce.Do(func() {
		transport := &http.Transport{}
		if p.Insecure {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		p.client = &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}
	})
	return p.client
}

func (p *Provider) getDescription() string {
	if p.Description != "" {
		return p.Description
	}
	return "Managed by Caddy"
}

func (p *Provider) getLogger() *zap.Logger {
	if p.Logger != nil {
		return p.Logger
	}
	return zap.NewNop()
}

func (p *Provider) baseURL() string {
	return fmt.Sprintf("https://%s/api/unbound", p.Host)
}

func (p *Provider) doRequest(ctx context.Context, method, endpoint string, body io.Reader) ([]byte, error) {
	url := p.baseURL() + "/" + endpoint
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.SetBasicAuth(p.APIKey, p.APISecret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.getClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (p *Provider) searchHostOverrides(ctx context.Context) ([]unboundHostOverride, error) {
	// Unbound uses POST for search_host_override
	respBody, err := p.doRequest(ctx, http.MethodPost, "settings/search_host_override", nil)
	if err != nil {
		return nil, err
	}

	var result searchHostOverrideResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return result.Rows, nil
}

func (p *Provider) addHostOverride(ctx context.Context, hostname, domain, ip string) error {
	// Determine record type from IP
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("invalid IP address: %w", err)
	}

	rr := "A"
	if addr.Is6() {
		rr = "AAAA"
	}

	p.getLogger().Debug("adding host override",
		zap.String("hostname", hostname),
		zap.String("domain", domain),
		zap.String("type", rr),
		zap.String("ip", ip))

	reqData := addHostOverrideRequest{
		Host: addHostOverrideData{
			Enabled:     "1",
			Hostname:    hostname,
			Domain:      domain,
			RR:          rr,
			MXPrio:      "",
			MX:          "",
			Server:      ip,
			Description: p.getDescription(),
		},
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	respBody, err := p.doRequest(ctx, http.MethodPost, "settings/add_host_override", strings.NewReader(string(reqBody)))
	if err != nil {
		return err
	}

	var result apiResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if result.Result != "saved" {
		return fmt.Errorf("failed to add host override: %s", result.Message)
	}

	return nil
}

func (p *Provider) deleteHostOverride(ctx context.Context, uuid string) error {
	p.getLogger().Debug("deleting host override", zap.String("uuid", uuid))

	respBody, err := p.doRequest(ctx, http.MethodPost, "settings/del_host_override/"+uuid, nil)
	if err != nil {
		return err
	}

	var result apiResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if result.Result != "deleted" {
		return fmt.Errorf("failed to delete host override: %s", result.Message)
	}

	return nil
}

func (p *Provider) reconfigure(ctx context.Context) error {
	p.getLogger().Debug("reconfiguring unbound service")

	respBody, err := p.doRequest(ctx, http.MethodPost, "service/reconfigure", nil)
	if err != nil {
		return err
	}

	var result apiResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if result.Status != "ok" {
		return fmt.Errorf("failed to reconfigure: %s", result.Message)
	}

	p.getLogger().Info("unbound service reconfigured")
	return nil
}

// getCleanupDelay returns the cleanup delay, defaulting to DefaultCleanupDelay
func (p *Provider) getCleanupDelay() time.Duration {
	if p.CleanupDelay > 0 {
		return p.CleanupDelay
	}
	return DefaultCleanupDelay
}

// trackManagedRecord marks a record as actively managed in the current session
func (p *Provider) trackManagedRecord(hostname, domain string) {
	p.syncMu.Lock()
	defer p.syncMu.Unlock()

	if p.managedRecords == nil {
		p.managedRecords = make(map[string]struct{})
	}
	if p.syncZones == nil {
		p.syncZones = make(map[string]struct{})
	}

	key := hostname + ":" + domain
	p.managedRecords[key] = struct{}{}
	p.syncZones[domain] = struct{}{}
}

// startCleanupTimer starts or resets the debounced cleanup timer
func (p *Provider) startCleanupTimer() {
	p.syncMu.Lock()
	defer p.syncMu.Unlock()

	// Stop existing timer if running
	if p.syncTimer != nil {
		p.syncTimer.Stop()
	}

	// Start new timer
	p.syncTimer = time.AfterFunc(p.getCleanupDelay(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		p.cleanupOrphanedRecords(ctx)
	})
}

// cleanupOrphanedRecords deletes records that have our description but weren't touched this session
func (p *Provider) cleanupOrphanedRecords(ctx context.Context) {
	p.syncMu.Lock()
	zones := p.syncZones
	managed := p.managedRecords
	// Reset tracking for next session
	p.syncZones = make(map[string]struct{})
	p.managedRecords = make(map[string]struct{})
	p.syncMu.Unlock()

	if len(zones) == 0 {
		return
	}

	p.getLogger().Debug("starting orphan cleanup",
		zap.Int("managed_records", len(managed)),
		zap.Int("zones", len(zones)))

	// Query all host overrides
	hosts, err := p.searchHostOverrides(ctx)
	if err != nil {
		p.getLogger().Error("failed to search host overrides for cleanup", zap.Error(err))
		return
	}

	needsReconfigure := false
	for _, h := range hosts {
		// Skip if not our description
		if h.Description != p.getDescription() {
			continue
		}
		// Skip if not in a touched zone
		if _, ok := zones[h.Domain]; !ok {
			continue
		}
		// Skip if record was managed this session
		key := h.Hostname + ":" + h.Domain
		if _, ok := managed[key]; ok {
			continue
		}

		// Delete orphaned record
		p.getLogger().Info("deleting orphaned DNS record",
			zap.String("hostname", h.Hostname),
			zap.String("domain", h.Domain),
			zap.String("ip", h.Server))
		if err := p.deleteHostOverride(ctx, h.UUID); err != nil {
			p.getLogger().Error("failed to delete orphaned host override",
				zap.String("hostname", h.Hostname),
				zap.String("domain", h.Domain),
				zap.Error(err))
			continue
		}
		needsReconfigure = true
	}

	if needsReconfigure {
		if err := p.reconfigure(ctx); err != nil {
			p.getLogger().Error("failed to reconfigure after cleanup", zap.Error(err))
		}
	}

	p.getLogger().Debug("orphan cleanup completed")
}

// trimZone removes the trailing dot from a zone name
func trimZone(zone string) string {
	return strings.TrimSuffix(zone, ".")
}

// resolveHostAndDomain handles the special case where name is "@" (zone apex).
// For unbound, we need to split the zone into hostname and domain parts.
// e.g., zone "my_domain.com" with name "@" becomes hostname "my_domain" and domain "com"
func resolveHostAndDomain(name, zone string) (hostname, domain string) {
	zone = trimZone(zone)
	if name == "@" || name == "" {
		// Zone apex: split the zone at the first dot
		if idx := strings.Index(zone, "."); idx > 0 {
			return zone[:idx], zone[idx+1:]
		}
		// No dot in zone, use zone as hostname with empty domain (edge case)
		return zone, ""
	}
	// Normal subdomain
	return name, zone
}

// isWildcard checks if the name is a wildcard record
func isWildcard(name string) bool {
	return name == "*" || strings.HasPrefix(name, "*.")
}

// hostOverrideToRecord converts an unboundHostOverride to a libdns.Address record
func hostOverrideToRecord(h unboundHostOverride) (libdns.Address, error) {
	ip, err := netip.ParseAddr(h.Server)
	if err != nil {
		return libdns.Address{}, fmt.Errorf("parsing IP %q: %w", h.Server, err)
	}

	return libdns.Address{
		Name: h.Hostname,
		IP:   ip,
	}, nil
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.getLogger().Debug("getting records", zap.String("zone", zone))

	hosts, err := p.searchHostOverrides(ctx)
	if err != nil {
		return nil, fmt.Errorf("searching host overrides: %w", err)
	}

	zone = trimZone(zone)
	var records []libdns.Record

	for _, h := range hosts {
		var name string

		if h.Domain == zone {
			// Normal subdomain: hostname "example" in domain "my_domain.com"
			name = h.Hostname
		} else if h.Hostname+"."+h.Domain == zone {
			// Apex record: hostname "my_domain" in domain "com" for zone "my_domain.com"
			name = "@"
		} else {
			continue // not part of this zone
		}

		// Only return A and AAAA records
		rr := strings.Split(h.RR, " ")[0] // RR may contain extra info like "A (Address)"
		if rr != "A" && rr != "AAAA" {
			continue
		}

		ip, err := netip.ParseAddr(h.Server)
		if err != nil {
			continue // skip invalid entries
		}

		p.getLogger().Debug("found DNS record",
			zap.String("type", rr),
			zap.String("name", name),
			zap.String("zone", zone),
			zap.String("value", ip.String()))

		records = append(records, libdns.Address{
			Name: name,
			IP:   ip,
		})
	}

	p.getLogger().Debug("finished getting records",
		zap.String("zone", zone),
		zap.Int("count", len(records)))

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.getLogger().Debug("appending records",
		zap.String("zone", zone),
		zap.Int("count", len(records)))

	var added []libdns.Record

	for _, record := range records {
		rr := record.RR()

		// Only A and AAAA records are supported
		if rr.Type != "A" && rr.Type != "AAAA" {
			return added, fmt.Errorf("unsupported record type %q: only A and AAAA are supported", rr.Type)
		}

		// Parse and validate the IP address
		ip, err := netip.ParseAddr(rr.Data)
		if err != nil {
			return added, fmt.Errorf("invalid IP address %q: %w", rr.Data, err)
		}

		// Get the relative name (hostname part) and resolve hostname/domain for unbound
		name := libdns.RelativeName(rr.Name, zone)

		// Skip wildcard records - unbound doesn't support them
		if isWildcard(name) {
			p.getLogger().Warn("skipping wildcard record - unbound does not support wildcard host overrides, consider using dnsmasq instead",
				zap.String("record", name),
				zap.String("zone", zone))
			continue
		}

		p.getLogger().Info("appending DNS record",
			zap.String("zone", zone),
			zap.String("name", name),
			zap.String("type", rr.Type),
			zap.String("ip", ip.String()))

		hostname, domain := resolveHostAndDomain(name, zone)

		if err := p.addHostOverride(ctx, hostname, domain, ip.String()); err != nil {
			return added, fmt.Errorf("adding host override %q: %w", name, err)
		}

		added = append(added, libdns.Address{
			Name: name,
			IP:   ip,
		})
	}

	if len(added) > 0 {
		if err := p.reconfigure(ctx); err != nil {
			return added, fmt.Errorf("reconfiguring: %w", err)
		}
	}

	return added, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.getLogger().Debug("setting records",
		zap.String("zone", zone),
		zap.Int("count", len(records)))

	// Get existing host overrides
	existingHosts, err := p.searchHostOverrides(ctx)
	if err != nil {
		return nil, fmt.Errorf("searching host overrides: %w", err)
	}

	// Build a map of existing hosts by hostname:domain key
	existingByKey := make(map[string]unboundHostOverride)
	for _, h := range existingHosts {
		key := h.Hostname + ":" + h.Domain
		existingByKey[key] = h
	}

	var results []libdns.Record
	needsReconfigure := false

	for _, record := range records {
		rr := record.RR()

		// Only A and AAAA records are supported
		if rr.Type != "A" && rr.Type != "AAAA" {
			return results, fmt.Errorf("unsupported record type %q: only A and AAAA are supported", rr.Type)
		}

		// Parse and validate the IP address
		ip, err := netip.ParseAddr(rr.Data)
		if err != nil {
			return results, fmt.Errorf("invalid IP address %q: %w", rr.Data, err)
		}

		name := libdns.RelativeName(rr.Name, zone)

		// Skip wildcard records - unbound doesn't support them
		if isWildcard(name) {
			p.getLogger().Warn("skipping wildcard record - unbound does not support wildcard host overrides, consider using dnsmasq instead",
				zap.String("record", name),
				zap.String("zone", zone))
			continue
		}

		hostname, domain := resolveHostAndDomain(name, zone)
		key := hostname + ":" + domain

		// Track this record as managed for orphan cleanup
		p.trackManagedRecord(hostname, domain)

		// Check if an entry already exists
		if existing, ok := existingByKey[key]; ok {
			// Determine expected record type
			expectedRR := "A"
			if ip.Is6() {
				expectedRR = "AAAA"
			}

			// Parse the existing RR (may contain extra info like "A (Address)")
			existingRR := strings.Split(existing.RR, " ")[0]

			// Check if it's identical
			if existing.Enabled == "1" &&
				existing.Server == ip.String() &&
				existing.Description == p.getDescription() &&
				existingRR == expectedRR &&
				existing.MXPrio == "" &&
				existing.MX == "" {
				// Already correct, no changes needed
				p.getLogger().Debug("record already up to date",
					zap.String("zone", zone),
					zap.String("name", name),
					zap.String("type", expectedRR),
					zap.String("ip", ip.String()))
				results = append(results, libdns.Address{
					Name: name,
					IP:   ip,
				})
				continue
			}

			// Delete the old entry
			p.getLogger().Info("updating DNS record",
				zap.String("zone", zone),
				zap.String("name", name),
				zap.String("type", expectedRR),
				zap.String("old_ip", existing.Server),
				zap.String("new_ip", ip.String()))
			if err := p.deleteHostOverride(ctx, existing.UUID); err != nil {
				return results, fmt.Errorf("deleting existing host override %q: %w", name, err)
			}
		} else {
			// Determine record type for logging
			recType := "A"
			if ip.Is6() {
				recType = "AAAA"
			}
			p.getLogger().Info("creating DNS record",
				zap.String("zone", zone),
				zap.String("name", name),
				zap.String("type", recType),
				zap.String("ip", ip.String()))
		}

		// Add the new entry
		if err := p.addHostOverride(ctx, hostname, domain, ip.String()); err != nil {
			return results, fmt.Errorf("adding host override %q: %w", name, err)
		}
		needsReconfigure = true

		results = append(results, libdns.Address{
			Name: name,
			IP:   ip,
		})
	}

	if needsReconfigure {
		if err := p.reconfigure(ctx); err != nil {
			return results, fmt.Errorf("reconfiguring: %w", err)
		}
	}

	// Start cleanup timer (will be reset if more SetRecords calls come in)
	p.startCleanupTimer()

	return results, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.getLogger().Debug("deleting records",
		zap.String("zone", zone),
		zap.Int("count", len(records)))

	// Get existing host overrides
	existingHosts, err := p.searchHostOverrides(ctx)
	if err != nil {
		return nil, fmt.Errorf("searching host overrides: %w", err)
	}

	// Build a map of existing hosts by hostname:domain key
	existingByKey := make(map[string]unboundHostOverride)
	for _, h := range existingHosts {
		key := h.Hostname + ":" + h.Domain
		existingByKey[key] = h
	}

	var deleted []libdns.Record

	for _, record := range records {
		rr := record.RR()
		name := libdns.RelativeName(rr.Name, zone)
		hostname, domain := resolveHostAndDomain(name, zone)
		key := hostname + ":" + domain

		existing, ok := existingByKey[key]
		if !ok {
			p.getLogger().Debug("record not found, skipping delete",
				zap.String("zone", zone),
				zap.String("name", name))
			continue // record doesn't exist, nothing to delete
		}

		p.getLogger().Info("deleting DNS record",
			zap.String("zone", zone),
			zap.String("name", name),
			zap.String("ip", existing.Server))

		if err := p.deleteHostOverride(ctx, existing.UUID); err != nil {
			return deleted, fmt.Errorf("deleting host override %q: %w", name, err)
		}

		addr, err := hostOverrideToRecord(existing)
		if err != nil {
			continue
		}
		deleted = append(deleted, addr)
	}

	if len(deleted) > 0 {
		if err := p.reconfigure(ctx); err != nil {
			return deleted, fmt.Errorf("reconfiguring: %w", err)
		}
	}

	return deleted, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
