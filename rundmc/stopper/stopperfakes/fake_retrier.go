// This file was generated by counterfeiter
package stopperfakes

import (
	"sync"

	"code.cloudfoundry.org/guardian/rundmc/stopper"
)

type FakeRetrier struct {
	RunStub        func(work func() error) error
	runMutex       sync.RWMutex
	runArgsForCall []struct {
		work func() error
	}
	runReturns struct {
		result1 error
	}
	runReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeRetrier) Run(work func() error) error {
	fake.runMutex.Lock()
	ret, specificReturn := fake.runReturnsOnCall[len(fake.runArgsForCall)]
	fake.runArgsForCall = append(fake.runArgsForCall, struct {
		work func() error
	}{work})
	fake.recordInvocation("Run", []interface{}{work})
	fake.runMutex.Unlock()
	if fake.RunStub != nil {
		return fake.RunStub(work)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.runReturns.result1
}

func (fake *FakeRetrier) RunCallCount() int {
	fake.runMutex.RLock()
	defer fake.runMutex.RUnlock()
	return len(fake.runArgsForCall)
}

func (fake *FakeRetrier) RunArgsForCall(i int) func() error {
	fake.runMutex.RLock()
	defer fake.runMutex.RUnlock()
	return fake.runArgsForCall[i].work
}

func (fake *FakeRetrier) RunReturns(result1 error) {
	fake.RunStub = nil
	fake.runReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeRetrier) RunReturnsOnCall(i int, result1 error) {
	fake.RunStub = nil
	if fake.runReturnsOnCall == nil {
		fake.runReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.runReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeRetrier) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.runMutex.RLock()
	defer fake.runMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeRetrier) recordInvocation(key string, args []interface{}) {
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

var _ stopper.Retrier = new(FakeRetrier)
