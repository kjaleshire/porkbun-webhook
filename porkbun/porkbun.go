package porkbun

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/nrdcg/porkbun"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	klog "k8s.io/klog/v2"
)

type PorkbunSolver struct {
	kube *kubernetes.Clientset
}

func (e *PorkbunSolver) Name() string {
	return "porkbun"
}

type Config struct {
	ApiKeySecretRef    corev1.SecretKeySelector `json:"apiKeySecretRef"`
	SecretKeySecretRef corev1.SecretKeySelector `json:"secretKeySecretRef"`
}

func (e *PorkbunSolver) readConfig(request *acme.ChallengeRequest) (*porkbun.Client, error) {
	config := Config{}

	if request.Config != nil {
		if err := json.Unmarshal(request.Config.Raw, &config); err != nil {
			return nil, fmt.Errorf("config error: %s", err)
		}
	}

	apiKey, err := e.resolveSecretRef(config.ApiKeySecretRef, request)
	if err != nil {
		return nil, err
	}

	secretKey, err := e.resolveSecretRef(config.SecretKeySecretRef, request)
	if err != nil {
		return nil, err
	}

	return porkbun.New(secretKey, apiKey), nil
}

func (e *PorkbunSolver) resolveSecretRef(selector corev1.SecretKeySelector, ch *acme.ChallengeRequest) (string, error) {
	secret, err := e.kube.CoreV1().Secrets(ch.ResourceNamespace).Get(context.Background(), selector.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get error for secret %q %q: %s", ch.ResourceNamespace, selector.Name, err)
	}

	bytes, ok := secret.Data[selector.Key]
	if !ok {
		return "", fmt.Errorf("secret %q %q does not contain key %q: %s", ch.ResourceNamespace, selector.Name, selector.Key, err)
	}

	return string(bytes), nil
}

func (e *PorkbunSolver) Present(ch *acme.ChallengeRequest) error {
	klog.Infof("Handling present request for %q %q", ch.ResolvedFQDN, ch.Key)

	client, err := e.readConfig(ch)
	if err != nil {
		return fmt.Errorf("initialization error: %s", err)
	}

	domain := strings.TrimSuffix(ch.ResolvedZone, ".")
	entity := strings.TrimSuffix(ch.ResolvedFQDN, "."+ch.ResolvedZone)
	name := strings.TrimSuffix(ch.ResolvedFQDN, ".")
	records, err := client.RetrieveRecords(context.Background(), domain)
	if err != nil {
		return fmt.Errorf("retrieve records error: %s", err)
	}

	for _, record := range records {
		if record.Type == "TXT" && record.Name == name && record.Content == ch.Key {
			klog.Infof("Record %s is already present", record.ID)
			return nil
		}
	}

	id, err := client.CreateRecord(context.Background(), domain, porkbun.Record{
		Name:    entity,
		Type:    "TXT",
		Content: ch.Key,
		TTL:     "60",
	})
	if err != nil {
		return fmt.Errorf("create record error: %s", err)
	}

	klog.Infof("Created record %v", id)
	return nil
}

func (e *PorkbunSolver) CleanUp(ch *acme.ChallengeRequest) error {
	klog.Infof("Handling cleanup request for %q %q", ch.ResolvedFQDN, ch.Key)

	client, err := e.readConfig(ch)
	if err != nil {
		return fmt.Errorf("initialization error: %s", err)
	}

	domain := strings.TrimSuffix(ch.ResolvedZone, ".")
	name := strings.TrimSuffix(ch.ResolvedFQDN, ".")
	records, err := client.RetrieveRecords(context.Background(), domain)
	if err != nil {
		return fmt.Errorf("retrieve records error: %s", err)
	}

	for _, record := range records {
		if record.Type == "TXT" && record.Name == name && record.Content == ch.Key {
			id, err := strconv.ParseInt(record.ID, 10, 32)
			if err != nil {
				return fmt.Errorf("found TXT record, but it's ID is malformed: %s", err)
			}

			record.Content = ch.Key
			err = client.DeleteRecord(context.Background(), domain, int(id))
			if err != nil {
				return fmt.Errorf("delete record error: %s", err)
			}

			klog.Infof("Deleted record %v", id)
			return nil
		}
	}

	klog.Info("No matching record to delete")

	return nil
}

func (e *PorkbunSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	klog.Info("Initializing")

	kube, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("kube client creation error: %s", err)
	}

	e.kube = kube
	return nil
}

func New() webhook.Solver {
	return &PorkbunSolver{}
}
