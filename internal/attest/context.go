package attest

import "context"

type caKey struct{}

func Context(ctx context.Context, ca *CA) context.Context {
	return context.WithValue(ctx, caKey{}, ca)
}

func FromContext(ctx context.Context) (ca *CA, ok bool) {
	ca, ok = ctx.Value(caKey{}).(*CA)
	if !ok {
		return nil, ok
	}
	return ca, ca != nil
}
