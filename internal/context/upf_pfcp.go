package context

import (
	"context"
	"net"
	"time"

	"github.com/free5gc/smf/internal/pfcp/pfcptype"
)

const pfcpDNSLookupTimeout = time.Second

// pfcpIPs pins the configured FQDN's resolution for the current association.
// Active association traffic and source checks share the same result, so a
// transient DNS failure cannot invalidate an existing association. Cancellation
// clears the cache; no peer-supplied address is learned.
func (upf *UPF) pfcpIPs() []net.IP {
	if upf.NodeID.NodeIdType != pfcptype.NodeIdTypeFqdn {
		return []net.IP{upf.NodeID.IP}
	}
	upf.pfcpAddressMu.Lock()
	defer upf.pfcpAddressMu.Unlock()
	if len(upf.pfcpAddresses) != 0 || time.Now().Before(upf.pfcpResolveAfter) {
		return upf.pfcpAddresses
	}
	ctx, cancel := context.WithTimeout(context.Background(), pfcpDNSLookupTimeout)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, upf.NodeID.FQDN)
	// Bound retries even when a lookup fails or returns no usable addresses.
	upf.pfcpResolveAfter = time.Now().Add(30 * time.Second)
	if err == nil {
		for _, address := range addresses {
			if validPFCPIP(address.IP) {
				upf.pfcpAddresses = append(upf.pfcpAddresses, append(net.IP(nil), address.IP...))
			}
		}
	}
	return upf.pfcpAddresses
}

func validPFCPIP(ip net.IP) bool {
	return ip.To16() != nil && !ip.IsUnspecified() && !ip.IsMulticast()
}

func (upf *UPF) PFCPAddr() *net.UDPAddr {
	addr := &net.UDPAddr{Port: 8805}
	for _, ip := range upf.pfcpIPs() {
		if validPFCPIP(ip) {
			addr.IP = append(net.IP(nil), ip...)
			break
		}
	}
	return addr
}

// PFCPAddrForSetup refreshes a successful resolution before each disconnected
// setup attempt. This also lets retries follow DNS changes if the first attempt
// used an address that was already unavailable. Failed DNS lookups retain their
// cooldown, and an established or releasing association keeps its pinned address.
func (upf *UPF) PFCPAddrForSetup() *net.UDPAddr {
	upf.associationMu.RLock()
	defer upf.associationMu.RUnlock()
	if upf.associationState != AssociationEstablished && upf.associationState != AssociationReleasing {
		upf.pfcpAddressMu.Lock()
		if len(upf.pfcpAddresses) != 0 {
			upf.pfcpAddresses = nil
			upf.pfcpResolveAfter = time.Time{}
		}
		upf.pfcpAddressMu.Unlock()
	}
	return upf.PFCPAddr()
}

// resetPFCPAddresses requires associationMu to be held for writing. Keeping
// invalidation inside the generation check prevents an old cancellation from
// clearing the replacement association's addresses.
func (upf *UPF) resetPFCPAddresses() {
	upf.pfcpAddressMu.Lock()
	upf.pfcpAddresses = nil
	upf.pfcpResolveAfter = time.Time{}
	upf.pfcpAddressMu.Unlock()
}

// MatchesPFCPSource accepts any address resolved from the configured Node ID,
// including secondary IPv4/IPv6 addresses. It never trusts the UDP source itself.
func (upf *UPF) MatchesPFCPSource(source net.IP) bool {
	if !validPFCPIP(source) {
		return false
	}
	for _, expected := range upf.pfcpIPs() {
		if validPFCPIP(expected) && source.Equal(expected) {
			return true
		}
	}
	return false
}
