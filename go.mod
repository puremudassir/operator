module github.com/libopenstorage/operator

go 1.15

require (
	github.com/armon/go-metrics v0.3.3 // indirect
	github.com/coreos/go-oidc v2.2.1+incompatible // indirect
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/golang/mock v1.4.4
	github.com/google/shlex v0.0.0-20181106134648-c34317bd91bf
	github.com/grpc-ecosystem/go-grpc-middleware v1.1.0 // indirect
	github.com/hashicorp/consul/api v1.8.1 // indirect
	github.com/hashicorp/go-hclog v0.12.2 // indirect
	github.com/hashicorp/go-immutable-radix v1.2.0 // indirect
	github.com/hashicorp/go-msgpack v0.5.5 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2 // indirect
	github.com/hashicorp/go-version v1.2.1
	github.com/libopenstorage/cloudops v0.0.0-20190815012442-6e0d676b6c3e
	github.com/libopenstorage/openstorage v8.0.1-0.20200730032300-bef55ec5700c+incompatible
	github.com/mattn/go-colorable v0.1.7 // indirect
	github.com/miekg/dns v1.1.35 // indirect
	github.com/mitchellh/mapstructure v1.3.3 // indirect
	github.com/portworx/kvdb v0.0.0-20200723230726-2734b7f40194
	github.com/portworx/sched-ops v1.20.0-rc1
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.46.0
	github.com/prometheus-operator/prometheus-operator/pkg/client v0.46.0
	github.com/prometheus/client_golang v1.9.0 // indirect
	github.com/sirupsen/logrus v1.7.0
	github.com/stretchr/testify v1.6.1
	github.com/urfave/cli v1.22.2
	go.uber.org/atomic v1.7.0 // indirect
	golang.org/x/sync v0.0.0-20201207232520-09787c993a3a // indirect
	google.golang.org/grpc v1.33.2
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.20.4
	k8s.io/apiextensions-apiserver v0.20.4
	k8s.io/apimachinery v0.20.4
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v1.0.0
	k8s.io/kubernetes v1.20.4
	k8s.io/sample-controller v0.20.4
	k8s.io/utils v0.0.0-20201110183641-67b214c5f920
	sigs.k8s.io/cluster-api v0.2.11
	sigs.k8s.io/controller-runtime v0.8.0
)

replace (
	github.com/coreos/prometheus-operator => github.com/prometheus-operator/prometheus-operator v0.46.0
	github.com/hashicorp/consul => github.com/hashicorp/consul v1.5.1
	github.com/kubernetes-incubator/external-storage => github.com/libopenstorage/external-storage v5.1.1-0.20190919185747-9394ee8dd536+incompatible
	github.com/kubernetes-incubator/external-storage v0.0.0-00010101000000-000000000000 => github.com/libopenstorage/external-storage v5.1.1-0.20190919185747-9394ee8dd536+incompatible
	google.golang.org/grpc => google.golang.org/grpc v1.29.1
	google.golang.org/grpc/examples/helloworld/helloworld => google.golang.org/grpc/examples/helloworld/helloworld v1.29.1
	gopkg.in/fsnotify.v1 v1.4.7 => github.com/fsnotify/fsnotify v1.4.7
	k8s.io/api => k8s.io/api v0.20.4
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.20.4
	k8s.io/apimachinery => k8s.io/apimachinery v0.20.4
	k8s.io/apiserver => k8s.io/apiserver v0.20.4
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.20.4
	k8s.io/client-go => k8s.io/client-go v0.20.4
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.20.4
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.20.4
	k8s.io/code-generator => k8s.io/code-generator v0.20.4
	k8s.io/component-base => k8s.io/component-base v0.20.4
	k8s.io/component-helpers => k8s.io/component-helpers v0.20.4
	k8s.io/controller-manager => k8s.io/controller-manager v0.20.4
	k8s.io/cri-api => k8s.io/cri-api v0.20.4
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.20.4
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.20.4
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.20.4
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.20.4
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.20.4
	k8s.io/kubectl => k8s.io/kubectl v0.20.4
	k8s.io/kubelet => k8s.io/kubelet v0.20.4
	k8s.io/kubernetes => k8s.io/kubernetes v1.20.4
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.20.4
	k8s.io/metrics => k8s.io/metrics v0.20.4
	k8s.io/mount-utils => k8s.io/mount-utils v0.20.4
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.20.4
)