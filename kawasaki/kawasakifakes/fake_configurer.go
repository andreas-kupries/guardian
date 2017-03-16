// This file was generated by counterfeiter
package kawasakifakes

import (
	"sync"

	"code.cloudfoundry.org/guardian/kawasaki"
	"code.cloudfoundry.org/lager"
)

type FakeConfigurer struct {
	ApplyStub        func(log lager.Logger, cfg kawasaki.NetworkConfig, pid int) error
	applyMutex       sync.RWMutex
	applyArgsForCall []struct {
		log lager.Logger
		cfg kawasaki.NetworkConfig
		pid int
	}
	applyReturns struct {
		result1 error
	}
	applyReturnsOnCall map[int]struct {
		result1 error
	}
	DestroyBridgeStub        func(log lager.Logger, cfg kawasaki.NetworkConfig) error
	destroyBridgeMutex       sync.RWMutex
	destroyBridgeArgsForCall []struct {
		log lager.Logger
		cfg kawasaki.NetworkConfig
	}
	destroyBridgeReturns struct {
		result1 error
	}
	destroyBridgeReturnsOnCall map[int]struct {
		result1 error
	}
	DestroyIPTablesRulesStub        func(log lager.Logger, cfg kawasaki.NetworkConfig) error
	destroyIPTablesRulesMutex       sync.RWMutex
	destroyIPTablesRulesArgsForCall []struct {
		log lager.Logger
		cfg kawasaki.NetworkConfig
	}
	destroyIPTablesRulesReturns struct {
		result1 error
	}
	destroyIPTablesRulesReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeConfigurer) Apply(log lager.Logger, cfg kawasaki.NetworkConfig, pid int) error {
	fake.applyMutex.Lock()
	ret, specificReturn := fake.applyReturnsOnCall[len(fake.applyArgsForCall)]
	fake.applyArgsForCall = append(fake.applyArgsForCall, struct {
		log lager.Logger
		cfg kawasaki.NetworkConfig
		pid int
	}{log, cfg, pid})
	fake.recordInvocation("Apply", []interface{}{log, cfg, pid})
	fake.applyMutex.Unlock()
	if fake.ApplyStub != nil {
		return fake.ApplyStub(log, cfg, pid)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.applyReturns.result1
}

func (fake *FakeConfigurer) ApplyCallCount() int {
	fake.applyMutex.RLock()
	defer fake.applyMutex.RUnlock()
	return len(fake.applyArgsForCall)
}

func (fake *FakeConfigurer) ApplyArgsForCall(i int) (lager.Logger, kawasaki.NetworkConfig, int) {
	fake.applyMutex.RLock()
	defer fake.applyMutex.RUnlock()
	return fake.applyArgsForCall[i].log, fake.applyArgsForCall[i].cfg, fake.applyArgsForCall[i].pid
}

func (fake *FakeConfigurer) ApplyReturns(result1 error) {
	fake.ApplyStub = nil
	fake.applyReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeConfigurer) ApplyReturnsOnCall(i int, result1 error) {
	fake.ApplyStub = nil
	if fake.applyReturnsOnCall == nil {
		fake.applyReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.applyReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeConfigurer) DestroyBridge(log lager.Logger, cfg kawasaki.NetworkConfig) error {
	fake.destroyBridgeMutex.Lock()
	ret, specificReturn := fake.destroyBridgeReturnsOnCall[len(fake.destroyBridgeArgsForCall)]
	fake.destroyBridgeArgsForCall = append(fake.destroyBridgeArgsForCall, struct {
		log lager.Logger
		cfg kawasaki.NetworkConfig
	}{log, cfg})
	fake.recordInvocation("DestroyBridge", []interface{}{log, cfg})
	fake.destroyBridgeMutex.Unlock()
	if fake.DestroyBridgeStub != nil {
		return fake.DestroyBridgeStub(log, cfg)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.destroyBridgeReturns.result1
}

func (fake *FakeConfigurer) DestroyBridgeCallCount() int {
	fake.destroyBridgeMutex.RLock()
	defer fake.destroyBridgeMutex.RUnlock()
	return len(fake.destroyBridgeArgsForCall)
}

func (fake *FakeConfigurer) DestroyBridgeArgsForCall(i int) (lager.Logger, kawasaki.NetworkConfig) {
	fake.destroyBridgeMutex.RLock()
	defer fake.destroyBridgeMutex.RUnlock()
	return fake.destroyBridgeArgsForCall[i].log, fake.destroyBridgeArgsForCall[i].cfg
}

func (fake *FakeConfigurer) DestroyBridgeReturns(result1 error) {
	fake.DestroyBridgeStub = nil
	fake.destroyBridgeReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeConfigurer) DestroyBridgeReturnsOnCall(i int, result1 error) {
	fake.DestroyBridgeStub = nil
	if fake.destroyBridgeReturnsOnCall == nil {
		fake.destroyBridgeReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.destroyBridgeReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeConfigurer) DestroyIPTablesRules(log lager.Logger, cfg kawasaki.NetworkConfig) error {
	fake.destroyIPTablesRulesMutex.Lock()
	ret, specificReturn := fake.destroyIPTablesRulesReturnsOnCall[len(fake.destroyIPTablesRulesArgsForCall)]
	fake.destroyIPTablesRulesArgsForCall = append(fake.destroyIPTablesRulesArgsForCall, struct {
		log lager.Logger
		cfg kawasaki.NetworkConfig
	}{log, cfg})
	fake.recordInvocation("DestroyIPTablesRules", []interface{}{log, cfg})
	fake.destroyIPTablesRulesMutex.Unlock()
	if fake.DestroyIPTablesRulesStub != nil {
		return fake.DestroyIPTablesRulesStub(log, cfg)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.destroyIPTablesRulesReturns.result1
}

func (fake *FakeConfigurer) DestroyIPTablesRulesCallCount() int {
	fake.destroyIPTablesRulesMutex.RLock()
	defer fake.destroyIPTablesRulesMutex.RUnlock()
	return len(fake.destroyIPTablesRulesArgsForCall)
}

func (fake *FakeConfigurer) DestroyIPTablesRulesArgsForCall(i int) (lager.Logger, kawasaki.NetworkConfig) {
	fake.destroyIPTablesRulesMutex.RLock()
	defer fake.destroyIPTablesRulesMutex.RUnlock()
	return fake.destroyIPTablesRulesArgsForCall[i].log, fake.destroyIPTablesRulesArgsForCall[i].cfg
}

func (fake *FakeConfigurer) DestroyIPTablesRulesReturns(result1 error) {
	fake.DestroyIPTablesRulesStub = nil
	fake.destroyIPTablesRulesReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeConfigurer) DestroyIPTablesRulesReturnsOnCall(i int, result1 error) {
	fake.DestroyIPTablesRulesStub = nil
	if fake.destroyIPTablesRulesReturnsOnCall == nil {
		fake.destroyIPTablesRulesReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.destroyIPTablesRulesReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeConfigurer) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.applyMutex.RLock()
	defer fake.applyMutex.RUnlock()
	fake.destroyBridgeMutex.RLock()
	defer fake.destroyBridgeMutex.RUnlock()
	fake.destroyIPTablesRulesMutex.RLock()
	defer fake.destroyIPTablesRulesMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeConfigurer) recordInvocation(key string, args []interface{}) {
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

var _ kawasaki.Configurer = new(FakeConfigurer)
