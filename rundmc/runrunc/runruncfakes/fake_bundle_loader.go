// This file was generated by counterfeiter
package runruncfakes

import (
	"sync"

	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/runrunc"
)

type FakeBundleLoader struct {
	LoadStub        func(path string) (goci.Bndl, error)
	loadMutex       sync.RWMutex
	loadArgsForCall []struct {
		path string
	}
	loadReturns struct {
		result1 goci.Bndl
		result2 error
	}
	loadReturnsOnCall map[int]struct {
		result1 goci.Bndl
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeBundleLoader) Load(path string) (goci.Bndl, error) {
	fake.loadMutex.Lock()
	ret, specificReturn := fake.loadReturnsOnCall[len(fake.loadArgsForCall)]
	fake.loadArgsForCall = append(fake.loadArgsForCall, struct {
		path string
	}{path})
	fake.recordInvocation("Load", []interface{}{path})
	fake.loadMutex.Unlock()
	if fake.LoadStub != nil {
		return fake.LoadStub(path)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.loadReturns.result1, fake.loadReturns.result2
}

func (fake *FakeBundleLoader) LoadCallCount() int {
	fake.loadMutex.RLock()
	defer fake.loadMutex.RUnlock()
	return len(fake.loadArgsForCall)
}

func (fake *FakeBundleLoader) LoadArgsForCall(i int) string {
	fake.loadMutex.RLock()
	defer fake.loadMutex.RUnlock()
	return fake.loadArgsForCall[i].path
}

func (fake *FakeBundleLoader) LoadReturns(result1 goci.Bndl, result2 error) {
	fake.LoadStub = nil
	fake.loadReturns = struct {
		result1 goci.Bndl
		result2 error
	}{result1, result2}
}

func (fake *FakeBundleLoader) LoadReturnsOnCall(i int, result1 goci.Bndl, result2 error) {
	fake.LoadStub = nil
	if fake.loadReturnsOnCall == nil {
		fake.loadReturnsOnCall = make(map[int]struct {
			result1 goci.Bndl
			result2 error
		})
	}
	fake.loadReturnsOnCall[i] = struct {
		result1 goci.Bndl
		result2 error
	}{result1, result2}
}

func (fake *FakeBundleLoader) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.loadMutex.RLock()
	defer fake.loadMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeBundleLoader) recordInvocation(key string, args []interface{}) {
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

var _ runrunc.BundleLoader = new(FakeBundleLoader)
