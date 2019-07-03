/*
Copyright 2019 Openstorage.org

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	time "time"

	corev1alpha1 "github.com/libopenstorage/operator/pkg/apis/core/v1alpha1"
	versioned "github.com/libopenstorage/operator/pkg/client/clientset/versioned"
	internalinterfaces "github.com/libopenstorage/operator/pkg/client/informers/externalversions/internalinterfaces"
	v1alpha1 "github.com/libopenstorage/operator/pkg/client/listers/core/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// StorageNodeStatusInformer provides access to a shared informer and lister for
// StorageNodeStatuses.
type StorageNodeStatusInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.StorageNodeStatusLister
}

type storageNodeStatusInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewStorageNodeStatusInformer constructs a new informer for StorageNodeStatus type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewStorageNodeStatusInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredStorageNodeStatusInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredStorageNodeStatusInformer constructs a new informer for StorageNodeStatus type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredStorageNodeStatusInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CoreV1alpha1().StorageNodeStatuses(namespace).List(options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CoreV1alpha1().StorageNodeStatuses(namespace).Watch(options)
			},
		},
		&corev1alpha1.StorageNodeStatus{},
		resyncPeriod,
		indexers,
	)
}

func (f *storageNodeStatusInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredStorageNodeStatusInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *storageNodeStatusInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&corev1alpha1.StorageNodeStatus{}, f.defaultInformer)
}

func (f *storageNodeStatusInformer) Lister() v1alpha1.StorageNodeStatusLister {
	return v1alpha1.NewStorageNodeStatusLister(f.Informer().GetIndexer())
}