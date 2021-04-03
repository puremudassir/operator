package component

import (
	"github.com/hashicorp/go-version"
	pxutil "github.com/libopenstorage/operator/drivers/storage/portworx/util"
	corev1 "github.com/libopenstorage/operator/pkg/apis/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// TLSComponentName is the name for registering this component
	TLSComponentName = "TLS"
)

type tls struct {
}

func (t *tls) Name() string {
	return TLSComponentName
}

func (t *tls) Priority() int32 {
	return int32(0) // same as auth component
}

// Initialize initializes the componenet
func (t *tls) Initialize(
	_ client.Client,
	_ version.Version,
	_ *runtime.Scheme,
	_ record.EventRecorder,

) {
}

// IsEnabled checks if the components needs to be enabled based on the StorageCluster
func (t *tls) IsEnabled(cluster *corev1.StorageCluster) bool {
	return pxutil.IsTLSEnabledOnCluster(&cluster.Spec)
}

// Reconcile reconciles the component to match the current state of the StorageCluster
func (t *tls) Reconcile(cluster *corev1.StorageCluster) error {
	// if err := t.createDeployment(cluster, ownerRef); err != nil {
	// 	return err
	// }
	return nil
}

// Delete deletes the component if present
func (t *tls) Delete(cluster *corev1.StorageCluster) error {
	return nil
}

func (t *tls) MarkDeleted() {
}

// RegisterAuthComponent registers the auth component
func RegisterTLSComponent() {
	Register(TLSComponentName, &tls{})
}

func init() {
	RegisterTLSComponent()
}
