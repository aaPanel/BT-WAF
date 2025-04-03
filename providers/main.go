package providers

import (
	clusterCommon "CloudWaf/public/cluster_core/common"
	"sync"
)

var (
	provideHandlers        = make([]func(), 0, 256)
	clusterProvideHandlers = make([]func(), 0, 256)
	alwaysProvideHandlers  = make([]func(), 0, 256)
	mutex                  = sync.Mutex{}
)

func registerProviderAlways(handler func()) {
	mutex.Lock()
	defer mutex.Unlock()
	alwaysProvideHandlers = append(alwaysProvideHandlers, handler)
}

func registerProvider(handler func()) {
	if clusterCommon.ClusterState() == clusterCommon.CLUSTER_UPPER {
		return
	}
	mutex.Lock()
	defer mutex.Unlock()
	provideHandlers = append(provideHandlers, handler)
}

func registerProviderCluster(handler func()) {
	if clusterCommon.ClusterState() != clusterCommon.CLUSTER_UPPER {
		return
	}
	mutex.Lock()
	defer mutex.Unlock()
	clusterProvideHandlers = append(clusterProvideHandlers, handler)
}

func Provide() {
	ProvideAlways()
	if clusterCommon.ClusterState() == clusterCommon.CLUSTER_UPPER {
		ProvideCluster()
		return
	}
	mutex.Lock()
	defer mutex.Unlock()
	for _, f := range provideHandlers {
		if f != nil {
			f()
		}
	}
	provideHandlers = provideHandlers[:0]
}

func ProvideAlways() {
	mutex.Lock()
	defer mutex.Unlock()

	for _, f := range alwaysProvideHandlers {
		if f != nil {
			f()
		}
	}

	alwaysProvideHandlers = alwaysProvideHandlers[:0]
}

func ProvideCluster() {
	mutex.Lock()
	defer mutex.Unlock()

	for _, f := range clusterProvideHandlers {
		if f != nil {
			f()
		}
	}
	clusterProvideHandlers = clusterProvideHandlers[:0]
}
