package kawasaki_test

import (
	"net"

	"code.cloudfoundry.org/guardian/kawasaki"
	fakes "code.cloudfoundry.org/guardian/kawasaki/kawasakifakes"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lager/lagertest"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ConfigCreator", func() {
	var (
		creator              *kawasaki.Creator
		subnet               *net.IPNet
		ip                   net.IP
		externalIP           net.IP
		dnsServers           []net.IP
		additionalDNSServers []net.IP
		logger               lager.Logger
		idGenerator          *fakes.FakeIDGenerator
		mtu                  int
	)

	BeforeEach(func() {
		var err error
		ip, subnet, err = net.ParseCIDR("192.168.12.20/24")
		Expect(err).NotTo(HaveOccurred())

		externalIP = net.ParseIP("220.10.120.5")
		dnsServers = []net.IP{
			net.ParseIP("8.8.8.8"),
			net.ParseIP("8.8.4.4"),
		}
		additionalDNSServers = []net.IP{
			net.ParseIP("1.2.3.4"),
		}

		logger = lagertest.NewTestLogger("test")
		idGenerator = &fakes.FakeIDGenerator{}

		mtu = 1234

		creator = kawasaki.NewConfigCreator(idGenerator, "w1", "0123456789abcdef", externalIP, dnsServers, additionalDNSServers, mtu)
	})

	It("panics if the interface prefix is longer than 2 characters", func() {
		Expect(func() {
			kawasaki.NewConfigCreator(idGenerator, "too-long", "wc", externalIP, dnsServers, additionalDNSServers, mtu)
		}).To(Panic())
	})

	It("panics if the chain prefix is longer than 16 characters", func() {
		Expect(func() {
			kawasaki.NewConfigCreator(idGenerator, "w1", "0123456789abcdefg", externalIP, dnsServers, additionalDNSServers, mtu)
		}).To(Panic())
	})

	It("assigns the same bridge name to all IPs in the same subnet", func() {
		config1, err := creator.Create(logger, "banana", subnet, ip)
		Expect(err).NotTo(HaveOccurred())

		config2, err := creator.Create(logger, "banana", subnet, net.ParseIP("3.4.5.6"))
		Expect(err).NotTo(HaveOccurred())

		Expect(config1.BridgeName).To(Equal(config2.BridgeName))
	})

	Context("when the subnet IP is of the form xxx.xxx.xxx.xxx", func() {
		BeforeEach(func() {
			var err error

			ip, subnet, err = net.ParseCIDR("123.122.180.191/24")
			Expect(err).NotTo(HaveOccurred())
		})

		It("does not assign a bridge name that is longer than 15 chars", func() {
			config, err := creator.Create(logger, "banana", subnet, ip)
			Expect(err).NotTo(HaveOccurred())

			Expect(len(config.BridgeName)).To(BeNumerically("<=", 15))
		})

		It("starts all bridge names with the interface prefix then the string 'brdg-'", func() {
			config, err := creator.Create(logger, "banana", subnet, ip)
			Expect(err).NotTo(HaveOccurred())

			Expect(config.BridgeName).To(HavePrefix("w1brdg-"))
		})
	})

	It("assigns the interface names based on the ID from the ID generator", func() {
		idGenerator.GenerateReturns("cocacola")

		config, err := creator.Create(logger, "bananashmanana", subnet, ip)
		Expect(err).NotTo(HaveOccurred())

		Expect(config.HostIntf).To(Equal("w1cocacola-0"))
		Expect(config.ContainerIntf).To(Equal("w1cocacola-1"))
		Expect(config.IPTablePrefix).To(Equal("0123456789abcdef"))
		Expect(config.IPTableInstance).To(Equal("cocacola"))
	})

	It("only generates 1 ID per invocation", func() {
		_, err := creator.Create(logger, "bananashmanana", subnet, ip)
		Expect(err).NotTo(HaveOccurred())

		Expect(idGenerator.GenerateCallCount()).To(Equal(1))
	})

	It("saves the external ip", func() {
		config, err := creator.Create(logger, "banana", subnet, ip)
		Expect(err).NotTo(HaveOccurred())

		Expect(config.ExternalIP.String()).To(Equal("220.10.120.5"))
	})

	It("saves the subnet and ip", func() {
		config, err := creator.Create(logger, "banana", subnet, ip)
		Expect(err).NotTo(HaveOccurred())

		Expect(config.ContainerIP.String()).To(Equal("192.168.12.20"))
		Expect(config.Subnet.String()).To(Equal("192.168.12.0/24"))
	})

	It("assigns the bridge IP as the first IP in the subnet", func() {
		config, err := creator.Create(logger, "banana", subnet, ip)
		Expect(err).NotTo(HaveOccurred())

		Expect(config.BridgeIP.String()).To(Equal("192.168.12.1"))
	})

	It("assigns the mtu", func() {
		config, err := creator.Create(logger, "banana", subnet, ip)
		Expect(err).NotTo(HaveOccurred())

		Expect(config.Mtu).To(Equal(1234))
	})

	It("Assigns the DNS servers", func() {
		config, err := creator.Create(logger, "banana", subnet, ip)
		Expect(err).NotTo(HaveOccurred())

		Expect(config.DNSServers).To(Equal(dnsServers))
	})

	It("Assigns the Additional DNS servers", func() {
		config, err := creator.Create(logger, "banana", subnet, ip)
		Expect(err).NotTo(HaveOccurred())

		Expect(config.AdditionalDNSServers).To(Equal(additionalDNSServers))
	})
})
