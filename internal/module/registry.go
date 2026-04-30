package module

import "fmt"

// Factory creates a fresh, unconfigured Module.
type Factory func() Module

// registry holds compiled-in module factories keyed by Name(). Modules
// register themselves via init() in their own packages.
var registry = map[string]Factory{}

// Register adds a module factory. Panics on duplicate name — there's no
// scenario where overwriting a known module silently is the right call.
func Register(name string, f Factory) {
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("module already registered: %s", name))
	}
	registry[name] = f
}

// New instantiates a module by name, returning an error if no factory is
// registered.
func New(name string) (Module, error) {
	f, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown module: %s", name)
	}
	return f(), nil
}

// Names returns all registered module names in stable order. Useful for
// CLI help text.
func Names() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	return out
}
