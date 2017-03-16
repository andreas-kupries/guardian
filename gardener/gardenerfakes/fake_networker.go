// This file was generated by counterfeiter
package gardenerfakes

import (
	"sync"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/gardener"
	"code.cloudfoundry.org/lager"
)

type FakeNetworker struct {
	NetworkStub        func(log lager.Logger, spec garden.ContainerSpec, pid int) error
	networkMutex       sync.RWMutex
	networkArgsForCall []struct {
		log  lager.Logger
		spec garden.ContainerSpec
		pid  int
	}
	networkReturns struct {
		result1 error
	}
	networkReturnsOnCall map[int]struct {
		result1 error
	}
	CapacityStub        func() uint64
	capacityMutex       sync.RWMutex
	capacityArgsForCall []struct{}
	capacityReturns     struct {
		result1 uint64
	}
	capacityReturnsOnCall map[int]struct {
		result1 uint64
	}
	DestroyStub        func(log lager.Logger, handle string) error
	destroyMutex       sync.RWMutex
	destroyArgsForCall []struct {
		log    lager.Logger
		handle string
	}
	destroyReturns struct {
		result1 error
	}
	destroyReturnsOnCall map[int]struct {
		result1 error
	}
	NetInStub        func(log lager.Logger, handle string, hostPort, containerPort uint32) (uint32, uint32, error)
	netInMutex       sync.RWMutex
	netInArgsForCall []struct {
		log           lager.Logger
		handle        string
		hostPort      uint32
		containerPort uint32
	}
	netInReturns struct {
		result1 uint32
		result2 uint32
		result3 error
	}
	netInReturnsOnCall map[int]struct {
		result1 uint32
		result2 uint32
		result3 error
	}
	BulkNetOutStub        func(log lager.Logger, handle string, rules []garden.NetOutRule) error
	bulkNetOutMutex       sync.RWMutex
	bulkNetOutArgsForCall []struct {
		log    lager.Logger
		handle string
		rules  []garden.NetOutRule
	}
	bulkNetOutReturns struct {
		result1 error
	}
	bulkNetOutReturnsOnCall map[int]struct {
		result1 error
	}
	NetOutStub        func(log lager.Logger, handle string, rule garden.NetOutRule) error
	netOutMutex       sync.RWMutex
	netOutArgsForCall []struct {
		log    lager.Logger
		handle string
		rule   garden.NetOutRule
	}
	netOutReturns struct {
		result1 error
	}
	netOutReturnsOnCall map[int]struct {
		result1 error
	}
	RestoreStub        func(log lager.Logger, handle string) error
	restoreMutex       sync.RWMutex
	restoreArgsForCall []struct {
		log    lager.Logger
		handle string
	}
	restoreReturns struct {
		result1 error
	}
	restoreReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeNetworker) Network(log lager.Logger, spec garden.ContainerSpec, pid int) error {
	fake.networkMutex.Lock()
	ret, specificReturn := fake.networkReturnsOnCall[len(fake.networkArgsForCall)]
	fake.networkArgsForCall = append(fake.networkArgsForCall, struct {
		log  lager.Logger
		spec garden.ContainerSpec
		pid  int
	}{log, spec, pid})
	fake.recordInvocation("Network", []interface{}{log, spec, pid})
	fake.networkMutex.Unlock()
	if fake.NetworkStub != nil {
		return fake.NetworkStub(log, spec, pid)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.networkReturns.result1
}

func (fake *FakeNetworker) NetworkCallCount() int {
	fake.networkMutex.RLock()
	defer fake.networkMutex.RUnlock()
	return len(fake.networkArgsForCall)
}

func (fake *FakeNetworker) NetworkArgsForCall(i int) (lager.Logger, garden.ContainerSpec, int) {
	fake.networkMutex.RLock()
	defer fake.networkMutex.RUnlock()
	return fake.networkArgsForCall[i].log, fake.networkArgsForCall[i].spec, fake.networkArgsForCall[i].pid
}

func (fake *FakeNetworker) NetworkReturns(result1 error) {
	fake.NetworkStub = nil
	fake.networkReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeNetworker) NetworkReturnsOnCall(i int, result1 error) {
	fake.NetworkStub = nil
	if fake.networkReturnsOnCall == nil {
		fake.networkReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.networkReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeNetworker) Capacity() uint64 {
	fake.capacityMutex.Lock()
	ret, specificReturn := fake.capacityReturnsOnCall[len(fake.capacityArgsForCall)]
	fake.capacityArgsForCall = append(fake.capacityArgsForCall, struct{}{})
	fake.recordInvocation("Capacity", []interface{}{})
	fake.capacityMutex.Unlock()
	if fake.CapacityStub != nil {
		return fake.CapacityStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.capacityReturns.result1
}

func (fake *FakeNetworker) CapacityCallCount() int {
	fake.capacityMutex.RLock()
	defer fake.capacityMutex.RUnlock()
	return len(fake.capacityArgsForCall)
}

func (fake *FakeNetworker) CapacityReturns(result1 uint64) {
	fake.CapacityStub = nil
	fake.capacityReturns = struct {
		result1 uint64
	}{result1}
}

func (fake *FakeNetworker) CapacityReturnsOnCall(i int, result1 uint64) {
	fake.CapacityStub = nil
	if fake.capacityReturnsOnCall == nil {
		fake.capacityReturnsOnCall = make(map[int]struct {
			result1 uint64
		})
	}
	fake.capacityReturnsOnCall[i] = struct {
		result1 uint64
	}{result1}
}

func (fake *FakeNetworker) Destroy(log lager.Logger, handle string) error {
	fake.destroyMutex.Lock()
	ret, specificReturn := fake.destroyReturnsOnCall[len(fake.destroyArgsForCall)]
	fake.destroyArgsForCall = append(fake.destroyArgsForCall, struct {
		log    lager.Logger
		handle string
	}{log, handle})
	fake.recordInvocation("Destroy", []interface{}{log, handle})
	fake.destroyMutex.Unlock()
	if fake.DestroyStub != nil {
		return fake.DestroyStub(log, handle)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.destroyReturns.result1
}

func (fake *FakeNetworker) DestroyCallCount() int {
	fake.destroyMutex.RLock()
	defer fake.destroyMutex.RUnlock()
	return len(fake.destroyArgsForCall)
}

func (fake *FakeNetworker) DestroyArgsForCall(i int) (lager.Logger, string) {
	fake.destroyMutex.RLock()
	defer fake.destroyMutex.RUnlock()
	return fake.destroyArgsForCall[i].log, fake.destroyArgsForCall[i].handle
}

func (fake *FakeNetworker) DestroyReturns(result1 error) {
	fake.DestroyStub = nil
	fake.destroyReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeNetworker) DestroyReturnsOnCall(i int, result1 error) {
	fake.DestroyStub = nil
	if fake.destroyReturnsOnCall == nil {
		fake.destroyReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.destroyReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeNetworker) NetIn(log lager.Logger, handle string, hostPort uint32, containerPort uint32) (uint32, uint32, error) {
	fake.netInMutex.Lock()
	ret, specificReturn := fake.netInReturnsOnCall[len(fake.netInArgsForCall)]
	fake.netInArgsForCall = append(fake.netInArgsForCall, struct {
		log           lager.Logger
		handle        string
		hostPort      uint32
		containerPort uint32
	}{log, handle, hostPort, containerPort})
	fake.recordInvocation("NetIn", []interface{}{log, handle, hostPort, containerPort})
	fake.netInMutex.Unlock()
	if fake.NetInStub != nil {
		return fake.NetInStub(log, handle, hostPort, containerPort)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	return fake.netInReturns.result1, fake.netInReturns.result2, fake.netInReturns.result3
}

func (fake *FakeNetworker) NetInCallCount() int {
	fake.netInMutex.RLock()
	defer fake.netInMutex.RUnlock()
	return len(fake.netInArgsForCall)
}

func (fake *FakeNetworker) NetInArgsForCall(i int) (lager.Logger, string, uint32, uint32) {
	fake.netInMutex.RLock()
	defer fake.netInMutex.RUnlock()
	return fake.netInArgsForCall[i].log, fake.netInArgsForCall[i].handle, fake.netInArgsForCall[i].hostPort, fake.netInArgsForCall[i].containerPort
}

func (fake *FakeNetworker) NetInReturns(result1 uint32, result2 uint32, result3 error) {
	fake.NetInStub = nil
	fake.netInReturns = struct {
		result1 uint32
		result2 uint32
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeNetworker) NetInReturnsOnCall(i int, result1 uint32, result2 uint32, result3 error) {
	fake.NetInStub = nil
	if fake.netInReturnsOnCall == nil {
		fake.netInReturnsOnCall = make(map[int]struct {
			result1 uint32
			result2 uint32
			result3 error
		})
	}
	fake.netInReturnsOnCall[i] = struct {
		result1 uint32
		result2 uint32
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeNetworker) BulkNetOut(log lager.Logger, handle string, rules []garden.NetOutRule) error {
	var rulesCopy []garden.NetOutRule
	if rules != nil {
		rulesCopy = make([]garden.NetOutRule, len(rules))
		copy(rulesCopy, rules)
	}
	fake.bulkNetOutMutex.Lock()
	ret, specificReturn := fake.bulkNetOutReturnsOnCall[len(fake.bulkNetOutArgsForCall)]
	fake.bulkNetOutArgsForCall = append(fake.bulkNetOutArgsForCall, struct {
		log    lager.Logger
		handle string
		rules  []garden.NetOutRule
	}{log, handle, rulesCopy})
	fake.recordInvocation("BulkNetOut", []interface{}{log, handle, rulesCopy})
	fake.bulkNetOutMutex.Unlock()
	if fake.BulkNetOutStub != nil {
		return fake.BulkNetOutStub(log, handle, rules)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.bulkNetOutReturns.result1
}

func (fake *FakeNetworker) BulkNetOutCallCount() int {
	fake.bulkNetOutMutex.RLock()
	defer fake.bulkNetOutMutex.RUnlock()
	return len(fake.bulkNetOutArgsForCall)
}

func (fake *FakeNetworker) BulkNetOutArgsForCall(i int) (lager.Logger, string, []garden.NetOutRule) {
	fake.bulkNetOutMutex.RLock()
	defer fake.bulkNetOutMutex.RUnlock()
	return fake.bulkNetOutArgsForCall[i].log, fake.bulkNetOutArgsForCall[i].handle, fake.bulkNetOutArgsForCall[i].rules
}

func (fake *FakeNetworker) BulkNetOutReturns(result1 error) {
	fake.BulkNetOutStub = nil
	fake.bulkNetOutReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeNetworker) BulkNetOutReturnsOnCall(i int, result1 error) {
	fake.BulkNetOutStub = nil
	if fake.bulkNetOutReturnsOnCall == nil {
		fake.bulkNetOutReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.bulkNetOutReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeNetworker) NetOut(log lager.Logger, handle string, rule garden.NetOutRule) error {
	fake.netOutMutex.Lock()
	ret, specificReturn := fake.netOutReturnsOnCall[len(fake.netOutArgsForCall)]
	fake.netOutArgsForCall = append(fake.netOutArgsForCall, struct {
		log    lager.Logger
		handle string
		rule   garden.NetOutRule
	}{log, handle, rule})
	fake.recordInvocation("NetOut", []interface{}{log, handle, rule})
	fake.netOutMutex.Unlock()
	if fake.NetOutStub != nil {
		return fake.NetOutStub(log, handle, rule)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.netOutReturns.result1
}

func (fake *FakeNetworker) NetOutCallCount() int {
	fake.netOutMutex.RLock()
	defer fake.netOutMutex.RUnlock()
	return len(fake.netOutArgsForCall)
}

func (fake *FakeNetworker) NetOutArgsForCall(i int) (lager.Logger, string, garden.NetOutRule) {
	fake.netOutMutex.RLock()
	defer fake.netOutMutex.RUnlock()
	return fake.netOutArgsForCall[i].log, fake.netOutArgsForCall[i].handle, fake.netOutArgsForCall[i].rule
}

func (fake *FakeNetworker) NetOutReturns(result1 error) {
	fake.NetOutStub = nil
	fake.netOutReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeNetworker) NetOutReturnsOnCall(i int, result1 error) {
	fake.NetOutStub = nil
	if fake.netOutReturnsOnCall == nil {
		fake.netOutReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.netOutReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeNetworker) Restore(log lager.Logger, handle string) error {
	fake.restoreMutex.Lock()
	ret, specificReturn := fake.restoreReturnsOnCall[len(fake.restoreArgsForCall)]
	fake.restoreArgsForCall = append(fake.restoreArgsForCall, struct {
		log    lager.Logger
		handle string
	}{log, handle})
	fake.recordInvocation("Restore", []interface{}{log, handle})
	fake.restoreMutex.Unlock()
	if fake.RestoreStub != nil {
		return fake.RestoreStub(log, handle)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.restoreReturns.result1
}

func (fake *FakeNetworker) RestoreCallCount() int {
	fake.restoreMutex.RLock()
	defer fake.restoreMutex.RUnlock()
	return len(fake.restoreArgsForCall)
}

func (fake *FakeNetworker) RestoreArgsForCall(i int) (lager.Logger, string) {
	fake.restoreMutex.RLock()
	defer fake.restoreMutex.RUnlock()
	return fake.restoreArgsForCall[i].log, fake.restoreArgsForCall[i].handle
}

func (fake *FakeNetworker) RestoreReturns(result1 error) {
	fake.RestoreStub = nil
	fake.restoreReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeNetworker) RestoreReturnsOnCall(i int, result1 error) {
	fake.RestoreStub = nil
	if fake.restoreReturnsOnCall == nil {
		fake.restoreReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.restoreReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeNetworker) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.networkMutex.RLock()
	defer fake.networkMutex.RUnlock()
	fake.capacityMutex.RLock()
	defer fake.capacityMutex.RUnlock()
	fake.destroyMutex.RLock()
	defer fake.destroyMutex.RUnlock()
	fake.netInMutex.RLock()
	defer fake.netInMutex.RUnlock()
	fake.bulkNetOutMutex.RLock()
	defer fake.bulkNetOutMutex.RUnlock()
	fake.netOutMutex.RLock()
	defer fake.netOutMutex.RUnlock()
	fake.restoreMutex.RLock()
	defer fake.restoreMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeNetworker) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ gardener.Networker = new(FakeNetworker)
