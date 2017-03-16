// This file was generated by counterfeiter
package rundmcfakes

import (
	"sync"

	"code.cloudfoundry.org/guardian/gardener"
	"code.cloudfoundry.org/guardian/rundmc"
	"code.cloudfoundry.org/guardian/rundmc/goci"
)

type FakeBundleGenerator struct {
	GenerateStub        func(spec gardener.DesiredContainerSpec) goci.Bndl
	generateMutex       sync.RWMutex
	generateArgsForCall []struct {
		spec gardener.DesiredContainerSpec
	}
	generateReturns struct {
		result1 goci.Bndl
	}
	generateReturnsOnCall map[int]struct {
		result1 goci.Bndl
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeBundleGenerator) Generate(spec gardener.DesiredContainerSpec) goci.Bndl {
	fake.generateMutex.Lock()
	ret, specificReturn := fake.generateReturnsOnCall[len(fake.generateArgsForCall)]
	fake.generateArgsForCall = append(fake.generateArgsForCall, struct {
		spec gardener.DesiredContainerSpec
	}{spec})
	fake.recordInvocation("Generate", []interface{}{spec})
	fake.generateMutex.Unlock()
	if fake.GenerateStub != nil {
		return fake.GenerateStub(spec)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.generateReturns.result1
}

func (fake *FakeBundleGenerator) GenerateCallCount() int {
	fake.generateMutex.RLock()
	defer fake.generateMutex.RUnlock()
	return len(fake.generateArgsForCall)
}

func (fake *FakeBundleGenerator) GenerateArgsForCall(i int) gardener.DesiredContainerSpec {
	fake.generateMutex.RLock()
	defer fake.generateMutex.RUnlock()
	return fake.generateArgsForCall[i].spec
}

func (fake *FakeBundleGenerator) GenerateReturns(result1 goci.Bndl) {
	fake.GenerateStub = nil
	fake.generateReturns = struct {
		result1 goci.Bndl
	}{result1}
}

func (fake *FakeBundleGenerator) GenerateReturnsOnCall(i int, result1 goci.Bndl) {
	fake.GenerateStub = nil
	if fake.generateReturnsOnCall == nil {
		fake.generateReturnsOnCall = make(map[int]struct {
			result1 goci.Bndl
		})
	}
	fake.generateReturnsOnCall[i] = struct {
		result1 goci.Bndl
	}{result1}
}

func (fake *FakeBundleGenerator) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.generateMutex.RLock()
	defer fake.generateMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeBundleGenerator) recordInvocation(key string, args []interface{}) {
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

var _ rundmc.BundleGenerator = new(FakeBundleGenerator)
