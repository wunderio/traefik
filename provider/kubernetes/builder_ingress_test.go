package kubernetes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func buildIngress(opts ...func(*netv1.Ingress)) *netv1.Ingress {
	i := &netv1.Ingress{}
	for _, opt := range opts {
		opt(i)
	}
	return i
}

func iNamespace(value string) func(*netv1.Ingress) {
	return func(i *netv1.Ingress) {
		i.Namespace = value
	}
}

func iAnnotation(name string, value string) func(*netv1.Ingress) {
	return func(i *netv1.Ingress) {
		if i.Annotations == nil {
			i.Annotations = make(map[string]string)
		}
		i.Annotations[name] = value
	}
}

func iRules(opts ...func(*netv1.IngressSpec)) func(*netv1.Ingress) {
	return func(i *netv1.Ingress) {
		s := &netv1.IngressSpec{}
		for _, opt := range opts {
			opt(s)
		}
		i.Spec = *s
	}
}

func iSpecBackends(opts ...func(*netv1.IngressSpec)) func(*netv1.Ingress) {
	return func(i *netv1.Ingress) {
		s := &netv1.IngressSpec{}
		for _, opt := range opts {
			opt(s)
		}
		i.Spec = *s
	}
}

func iSpecBackend(opts ...func(*netv1.IngressBackend)) func(*netv1.IngressSpec) {
	return func(s *netv1.IngressSpec) {
		p := &netv1.IngressBackend{}
		for _, opt := range opts {
			opt(p)
		}
		s.Backend = p
	}
}

func iIngressBackend(name string, port intstr.IntOrString) func(*netv1.IngressBackend) {
	return func(p *netv1.IngressBackend) {
		p.ServiceName = name
		p.ServicePort = port
	}
}

func iRule(opts ...func(*netv1.IngressRule)) func(*netv1.IngressSpec) {
	return func(spec *netv1.IngressSpec) {
		r := &netv1.IngressRule{}
		for _, opt := range opts {
			opt(r)
		}
		spec.Rules = append(spec.Rules, *r)
	}
}

func iHost(name string) func(*netv1.IngressRule) {
	return func(rule *netv1.IngressRule) {
		rule.Host = name
	}
}

func iPaths(opts ...func(*netv1.HTTPIngressRuleValue)) func(*netv1.IngressRule) {
	return func(rule *netv1.IngressRule) {
		rule.HTTP = &netv1.HTTPIngressRuleValue{}
		for _, opt := range opts {
			opt(rule.HTTP)
		}
	}
}

func onePath(opts ...func(*netv1.HTTPIngressPath)) func(*netv1.HTTPIngressRuleValue) {
	return func(irv *netv1.HTTPIngressRuleValue) {
		p := &netv1.HTTPIngressPath{}
		for _, opt := range opts {
			opt(p)
		}
		irv.Paths = append(irv.Paths, *p)
	}
}

func iPath(name string) func(*netv1.HTTPIngressPath) {
	return func(p *netv1.HTTPIngressPath) {
		p.Path = name
	}
}

func iBackend(name string, port intstr.IntOrString) func(*netv1.HTTPIngressPath) {
	return func(p *netv1.HTTPIngressPath) {
		p.Backend = netv1.IngressBackend{
			ServiceName: name,
			ServicePort: port,
		}
	}
}

func iTLSes(opts ...func(*netv1.IngressTLS)) func(*netv1.Ingress) {
	return func(i *netv1.Ingress) {
		for _, opt := range opts {
			iTLS := netv1.IngressTLS{}
			opt(&iTLS)
			i.Spec.TLS = append(i.Spec.TLS, iTLS)
		}
	}
}

func iTLS(secret string, hosts ...string) func(*netv1.IngressTLS) {
	return func(i *netv1.IngressTLS) {
		i.SecretName = secret
		i.Hosts = hosts
	}
}

// Test

func TestBuildIngress(t *testing.T) {
	i := buildIngress(
		iNamespace("testing"),
		iRules(
			iRule(iHost("foo"), iPaths(
				onePath(iPath("/bar"), iBackend("service1", intstr.FromInt(80))),
				onePath(iPath("/namedthing"), iBackend("service4", intstr.FromString("https")))),
			),
			iRule(iHost("bar"), iPaths(
				onePath(iBackend("service3", intstr.FromString("https"))),
				onePath(iBackend("service2", intstr.FromInt(802))),
			),
			),
		),
		iTLSes(
			iTLS("tls-secret", "foo"),
		),
	)

	assert.EqualValues(t, sampleIngress(), i)
}

func sampleIngress() *netv1.Ingress {
	return &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "testing",
		},
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{
				{
					Host: "foo",
					IngressRuleValue: netv1.IngressRuleValue{
						HTTP: &netv1.HTTPIngressRuleValue{
							Paths: []netv1.HTTPIngressPath{
								{
									Path: "/bar",
									Backend: netv1.IngressBackend{
										ServiceName: "service1",
										ServicePort: intstr.FromInt(80),
									},
								},
								{
									Path: "/namedthing",
									Backend: netv1.IngressBackend{
										ServiceName: "service4",
										ServicePort: intstr.FromString("https"),
									},
								},
							},
						},
					},
				},
				{
					Host: "bar",
					IngressRuleValue: netv1.IngressRuleValue{
						HTTP: &netv1.HTTPIngressRuleValue{
							Paths: []netv1.HTTPIngressPath{
								{
									Backend: netv1.IngressBackend{
										ServiceName: "service3",
										ServicePort: intstr.FromString("https"),
									},
								},
								{
									Backend: netv1.IngressBackend{
										ServiceName: "service2",
										ServicePort: intstr.FromInt(802),
									},
								},
							},
						},
					},
				},
			},
			TLS: []netv1.IngressTLS{
				{
					Hosts:      []string{"foo"},
					SecretName: "tls-secret",
				},
			},
		},
	}
}
