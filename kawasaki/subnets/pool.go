// The subnets package provides a subnet pool from which networks may be dynamically acquired or
// statically reserved.
package subnets

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"sync"

	"code.cloudfoundry.org/lager"
)

//go:generate counterfeiter -o fake_subnet_pool/fake_pool.go . Pool
type Pool interface {
	// Allocates an IP address and associates it with a subnet. The subnet is selected by the given SubnetSelector.
	// The IP address is selected by the given IPSelector.
	// Returns a subnet, an IP address, and if either selector fails, an error is returned.
	Acquire(string, lager.Logger, SubnetSelector, IPSelector, string) (*net.IPNet, net.IP, error)

	// Releases an IP address associated with an allocated subnet. If the subnet has no other IP
	// addresses associated with it, it is deallocated.
	// Returns an error if the given combination is not already in the pool.
	Release(string, *net.IPNet, net.IP) error

	// Remove an IP address so it appears to be associated with the given subnet.
	Remove(string, *net.IPNet, net.IP) error

	// Returns the number of /30 subnets which can be Acquired by a DynamicSubnetSelector.
	Capacity() int

	// Run the provided callback if the given subnet is not in use
	RunIfFree(*net.IPNet, func() error) error
}

type ipInfo struct {
	ip    net.IP // net.IPNet.String +> seq net.IP
	owner string
}

type pool struct {
	allocated    map[string][]ipInfo
	dynamicRange *net.IPNet
	mu           sync.Mutex
	log          lager.Logger
}

//go:generate counterfeiter . SubnetSelector

// SubnetSelector is a strategy for selecting a subnet.
type SubnetSelector interface {
	// Returns a subnet based on a dynamic range and some existing statically-allocated
	// subnets. If no suitable subnet can be found, returns an error.
	SelectSubnet(dynamic *net.IPNet, existing []*net.IPNet) (*net.IPNet, error)
}

//go:generate counterfeiter . IPSelector

// IPSelector is a strategy for selecting an IP address in a subnet.
type IPSelector interface {
	// Returns an IP address in the given subnet which is not one of the given existing
	// IP addresses. If no such IP address can be found, returns an error.
	SelectIP(subnet *net.IPNet, existing []net.IP) (net.IP, error)
}

func NewPool(ipNet *net.IPNet, log lager.Logger) Pool {
	r := &pool{dynamicRange: ipNet, allocated: make(map[string][]ipInfo)}
	session := log.Session("XXX").Session(fmt.Sprintf("%d-pool-%p", os.Getpid(), r))
	session.Info("new-pool", lager.Data{"net": ipNet})
	r.log = session
	return r
}

// Acquire uses the given subnet and IP selectors to request a subnet, container IP address combination
// from the pool.
func (p *pool) Acquire(owner string, log lager.Logger, sn SubnetSelector, i IPSelector, network string) (subnet *net.IPNet, ip net.IP, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	session := p.log.Session("acquire")
	session.Info("arguments", lager.Data{"network": network, "subnet": sn, "ipselector": i})
	session.Info("existing-nets", lager.Data{"have": existingSubnets(p.allocated)})

	if subnet, err = sn.SelectSubnet(p.dynamicRange, existingSubnets(p.allocated)); err != nil {
		session.Info("select-subnet-fail", lager.Data{"err": err})
		return nil, nil, err
	}

	log.Debug("select-subnet", lager.Data{"subnet": subnet, "network": network})

	session.Info("select-subnet", lager.Data{"subnet": subnet, "network": network})

	ips := justIPs(p.allocated[subnet.String()])
	existingIPs := append(ips, NetworkIP(subnet), GatewayIP(subnet), BroadcastIP(subnet))

	session.Info("existing-ips", lager.Data{"have": existingIPs})

	if ip, err = i.SelectIP(subnet, existingIPs); err != nil {
		session.Info("select-ip-fail", lager.Data{"err": err})
		return nil, nil, err
	}

	xips := p.allocated[subnet.String()]
	p.allocated[subnet.String()] = append(xips, ipInfo{
		ip:    ip,
		owner: owner,
	})

	session.Info("acquired", lager.Data{"subnet": subnet, "ip": ip, "network": network})
	session.Info("new-existing-nets", lager.Data{"have": existingSubnets(p.allocated)})
	session.Info("new-existing-ips", lager.Data{"have": p.allocated[subnet.String()]})
	session.Info("ok")

	return subnet, ip, err
}

// Recover (Remove?) [Replace?] re-allocates a given subnet and ip address combination in the pool. It returns
// an error if the combination is already allocated.
func (p *pool) Remove(owner string, subnet *net.IPNet, ip net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	session := p.log.Session("remove")
	session.Info("arguments", lager.Data{"subnet": subnet, "ip": ip})

	if ip == nil {
		session.Info("fail-nil-ip")
		return ErrIpCannotBeNil
	}

	session.Info("overlaps?")

	for _, existing := range p.allocated[subnet.String()] {
		if existing.ip.Equal(ip) {
			session.Info("fail-overlap", lager.Data{"want": ip, "conflict": existing})

			return ErrOverlapsExistingSubnet
		}
	}

	p.allocated[subnet.String()] = append(p.allocated[subnet.String()], ipInfo{
		ip:    ip,
		owner: owner,
	})

	session.Info("removed", lager.Data{"subnet": subnet, "ip": ip})
	session.Info("ok")
	return nil
}

func (p *pool) Release(owner string, subnet *net.IPNet, ip net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	session := p.log.Session("release")
	session.Info("arguments", lager.Data{"subnet": subnet, "ip": ip})

	subnetString := subnet.String()
	ips := p.allocated[subnetString]

	session.Info("subnet-ips", lager.Data{"ips": ips})

	if i, found := indexOf(ips, ip); found {
		// Owner mismatch. A new owner slipped into the window between partial and
		// full deletion of an app, and reclaimed the IP. Treat as if the IP is
		// already deleted, i.e. same as not found.
		if ips[i].owner != owner {
			session.Info("fail-unallocated")
			return ErrReleasedUnallocatedSubnet
		}

		session.Info("found", lager.Data{"at": i})

		if reducedIps, empty := removeIPAtIndex(ips, i); empty {
			delete(p.allocated, subnetString)

			session.Info("cleared", lager.Data{"subnet": subnet})
		} else {
			p.allocated[subnetString] = reducedIps

			session.Info("reduced", lager.Data{"subnet": subnet, "result": reducedIps})
		}

		session.Info("released", lager.Data{"subnet": subnet, "ip": ip})
		session.Info("ok")
		return nil
	}

	session.Info("fail-unallocated")
	return ErrReleasedUnallocatedSubnet
}

// Capacity returns the number of /30 subnets that can be allocated
// from the pool's dynamic allocation range.
func (m *pool) Capacity() int {
	masked, total := m.dynamicRange.Mask.Size()
	return int(math.Pow(2, float64(total-masked)) / 4)
}

func (p *pool) RunIfFree(subnet *net.IPNet, cb func() error) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	session := p.log.Session("run-if-free")
	session.Info("arguments", lager.Data{"subnet": subnet})

	if _, ok := p.allocated[subnet.String()]; ok {
		session.Info("used-skip")
		return nil
	}

	session.Info("run")

	err := cb()

	session.Info("run-result", lager.Data{"err": err})

	return err
}

func (p *pool) MarshalJSON() ([]byte, error) {
	data := map[string]interface{}{
		"allocated":    p.allocated,
		"dynamicRange": p.dynamicRange,
	}
	buf, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// Returns the gateway IP of a given subnet, which is always the maximum valid IP
func GatewayIP(subnet *net.IPNet) net.IP {
	return next(subnet.IP)
}

// Returns the network IP of a subnet.
func NetworkIP(subnet *net.IPNet) net.IP {
	return subnet.IP
}

// Returns the broadcast IP of a subnet.
func BroadcastIP(subnet *net.IPNet) net.IP {
	return max(subnet)
}

func justIPs(ips []ipInfo) (result []net.IP) {
	for _, v := range ips {
		result = append(result, v.ip)
	}
	return result
}

// returns the keys in the given map whose values are non-empty slices
func existingSubnets(m map[string][]ipInfo) (result []*net.IPNet) {
	for k, v := range m {
		if len(v) > 0 {
			_, ipn, err := net.ParseCIDR(k)
			if err != nil {
				panic(fmt.Sprintf("failed to parse a CIDR (%s) in the subnet pool: %s", k, err))
			}

			result = append(result, ipn)
		}
	}

	return result
}

func indexOf(a []ipInfo, w net.IP) (int, bool) {
	for i, v := range a {
		if v.ip.Equal(w) {
			return i, true
		}
	}

	return -1, false
}

// removeAtIndex removes from a slice at the given index,
// and returns the new slice and boolean, true iff the new slice is empty.
func removeIPAtIndex(ips []ipInfo, i int) ([]ipInfo, bool) {
	l := len(ips)
	ips[i] = ips[l-1]
	ips = ips[:l-1]
	return ips, l == 1
}
