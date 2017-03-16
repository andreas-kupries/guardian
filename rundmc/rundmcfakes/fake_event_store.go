// This file was generated by counterfeiter
package rundmcfakes

import (
	"sync"

	"code.cloudfoundry.org/guardian/rundmc"
)

type FakeEventStore struct {
	OnEventStub        func(id string, event string) error
	onEventMutex       sync.RWMutex
	onEventArgsForCall []struct {
		id    string
		event string
	}
	onEventReturns struct {
		result1 error
	}
	onEventReturnsOnCall map[int]struct {
		result1 error
	}
	EventsStub        func(id string) []string
	eventsMutex       sync.RWMutex
	eventsArgsForCall []struct {
		id string
	}
	eventsReturns struct {
		result1 []string
	}
	eventsReturnsOnCall map[int]struct {
		result1 []string
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeEventStore) OnEvent(id string, event string) error {
	fake.onEventMutex.Lock()
	ret, specificReturn := fake.onEventReturnsOnCall[len(fake.onEventArgsForCall)]
	fake.onEventArgsForCall = append(fake.onEventArgsForCall, struct {
		id    string
		event string
	}{id, event})
	fake.recordInvocation("OnEvent", []interface{}{id, event})
	fake.onEventMutex.Unlock()
	if fake.OnEventStub != nil {
		return fake.OnEventStub(id, event)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.onEventReturns.result1
}

func (fake *FakeEventStore) OnEventCallCount() int {
	fake.onEventMutex.RLock()
	defer fake.onEventMutex.RUnlock()
	return len(fake.onEventArgsForCall)
}

func (fake *FakeEventStore) OnEventArgsForCall(i int) (string, string) {
	fake.onEventMutex.RLock()
	defer fake.onEventMutex.RUnlock()
	return fake.onEventArgsForCall[i].id, fake.onEventArgsForCall[i].event
}

func (fake *FakeEventStore) OnEventReturns(result1 error) {
	fake.OnEventStub = nil
	fake.onEventReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeEventStore) OnEventReturnsOnCall(i int, result1 error) {
	fake.OnEventStub = nil
	if fake.onEventReturnsOnCall == nil {
		fake.onEventReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.onEventReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeEventStore) Events(id string) []string {
	fake.eventsMutex.Lock()
	ret, specificReturn := fake.eventsReturnsOnCall[len(fake.eventsArgsForCall)]
	fake.eventsArgsForCall = append(fake.eventsArgsForCall, struct {
		id string
	}{id})
	fake.recordInvocation("Events", []interface{}{id})
	fake.eventsMutex.Unlock()
	if fake.EventsStub != nil {
		return fake.EventsStub(id)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.eventsReturns.result1
}

func (fake *FakeEventStore) EventsCallCount() int {
	fake.eventsMutex.RLock()
	defer fake.eventsMutex.RUnlock()
	return len(fake.eventsArgsForCall)
}

func (fake *FakeEventStore) EventsArgsForCall(i int) string {
	fake.eventsMutex.RLock()
	defer fake.eventsMutex.RUnlock()
	return fake.eventsArgsForCall[i].id
}

func (fake *FakeEventStore) EventsReturns(result1 []string) {
	fake.EventsStub = nil
	fake.eventsReturns = struct {
		result1 []string
	}{result1}
}

func (fake *FakeEventStore) EventsReturnsOnCall(i int, result1 []string) {
	fake.EventsStub = nil
	if fake.eventsReturnsOnCall == nil {
		fake.eventsReturnsOnCall = make(map[int]struct {
			result1 []string
		})
	}
	fake.eventsReturnsOnCall[i] = struct {
		result1 []string
	}{result1}
}

func (fake *FakeEventStore) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.onEventMutex.RLock()
	defer fake.onEventMutex.RUnlock()
	fake.eventsMutex.RLock()
	defer fake.eventsMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeEventStore) recordInvocation(key string, args []interface{}) {
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

var _ rundmc.EventStore = new(FakeEventStore)
