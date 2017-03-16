// This file was generated by counterfeiter
package stopperfakes

import (
	"sync"

	"code.cloudfoundry.org/guardian/rundmc/stopper"
)

type FakeCgroupPathResolver struct {
	ResolveStub        func(cgroupName, subsystem string) (string, error)
	resolveMutex       sync.RWMutex
	resolveArgsForCall []struct {
		cgroupName string
		subsystem  string
	}
	resolveReturns struct {
		result1 string
		result2 error
	}
	resolveReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeCgroupPathResolver) Resolve(cgroupName string, subsystem string) (string, error) {
	fake.resolveMutex.Lock()
	ret, specificReturn := fake.resolveReturnsOnCall[len(fake.resolveArgsForCall)]
	fake.resolveArgsForCall = append(fake.resolveArgsForCall, struct {
		cgroupName string
		subsystem  string
	}{cgroupName, subsystem})
	fake.recordInvocation("Resolve", []interface{}{cgroupName, subsystem})
	fake.resolveMutex.Unlock()
	if fake.ResolveStub != nil {
		return fake.ResolveStub(cgroupName, subsystem)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.resolveReturns.result1, fake.resolveReturns.result2
}

func (fake *FakeCgroupPathResolver) ResolveCallCount() int {
	fake.resolveMutex.RLock()
	defer fake.resolveMutex.RUnlock()
	return len(fake.resolveArgsForCall)
}

func (fake *FakeCgroupPathResolver) ResolveArgsForCall(i int) (string, string) {
	fake.resolveMutex.RLock()
	defer fake.resolveMutex.RUnlock()
	return fake.resolveArgsForCall[i].cgroupName, fake.resolveArgsForCall[i].subsystem
}

func (fake *FakeCgroupPathResolver) ResolveReturns(result1 string, result2 error) {
	fake.ResolveStub = nil
	fake.resolveReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *FakeCgroupPathResolver) ResolveReturnsOnCall(i int, result1 string, result2 error) {
	fake.ResolveStub = nil
	if fake.resolveReturnsOnCall == nil {
		fake.resolveReturnsOnCall = make(map[int]struct {
			result1 string
			result2 error
		})
	}
	fake.resolveReturnsOnCall[i] = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *FakeCgroupPathResolver) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.resolveMutex.RLock()
	defer fake.resolveMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeCgroupPathResolver) recordInvocation(key string, args []interface{}) {
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

var _ stopper.CgroupPathResolver = new(FakeCgroupPathResolver)
