// Code generated by counterfeiter. DO NOT EDIT.
package rundmcfakes

import (
	"sync"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/rundmc"
	"code.cloudfoundry.org/lager"
)

type FakePeaCreator struct {
	CreatePeaStub        func(log lager.Logger, spec garden.ProcessSpec, ctrBundlePath string) (garden.Process, error)
	createPeaMutex       sync.RWMutex
	createPeaArgsForCall []struct {
		log           lager.Logger
		spec          garden.ProcessSpec
		ctrBundlePath string
	}
	createPeaReturns struct {
		result1 garden.Process
		result2 error
	}
	createPeaReturnsOnCall map[int]struct {
		result1 garden.Process
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakePeaCreator) CreatePea(log lager.Logger, spec garden.ProcessSpec, ctrBundlePath string) (garden.Process, error) {
	fake.createPeaMutex.Lock()
	ret, specificReturn := fake.createPeaReturnsOnCall[len(fake.createPeaArgsForCall)]
	fake.createPeaArgsForCall = append(fake.createPeaArgsForCall, struct {
		log           lager.Logger
		spec          garden.ProcessSpec
		ctrBundlePath string
	}{log, spec, ctrBundlePath})
	fake.recordInvocation("CreatePea", []interface{}{log, spec, ctrBundlePath})
	fake.createPeaMutex.Unlock()
	if fake.CreatePeaStub != nil {
		return fake.CreatePeaStub(log, spec, ctrBundlePath)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.createPeaReturns.result1, fake.createPeaReturns.result2
}

func (fake *FakePeaCreator) CreatePeaCallCount() int {
	fake.createPeaMutex.RLock()
	defer fake.createPeaMutex.RUnlock()
	return len(fake.createPeaArgsForCall)
}

func (fake *FakePeaCreator) CreatePeaArgsForCall(i int) (lager.Logger, garden.ProcessSpec, string) {
	fake.createPeaMutex.RLock()
	defer fake.createPeaMutex.RUnlock()
	return fake.createPeaArgsForCall[i].log, fake.createPeaArgsForCall[i].spec, fake.createPeaArgsForCall[i].ctrBundlePath
}

func (fake *FakePeaCreator) CreatePeaReturns(result1 garden.Process, result2 error) {
	fake.CreatePeaStub = nil
	fake.createPeaReturns = struct {
		result1 garden.Process
		result2 error
	}{result1, result2}
}

func (fake *FakePeaCreator) CreatePeaReturnsOnCall(i int, result1 garden.Process, result2 error) {
	fake.CreatePeaStub = nil
	if fake.createPeaReturnsOnCall == nil {
		fake.createPeaReturnsOnCall = make(map[int]struct {
			result1 garden.Process
			result2 error
		})
	}
	fake.createPeaReturnsOnCall[i] = struct {
		result1 garden.Process
		result2 error
	}{result1, result2}
}

func (fake *FakePeaCreator) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.createPeaMutex.RLock()
	defer fake.createPeaMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakePeaCreator) recordInvocation(key string, args []interface{}) {
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

var _ rundmc.PeaCreator = new(FakePeaCreator)
