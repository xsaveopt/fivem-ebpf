package module

import "fmt"

type Factory func() Module

var registry = map[string]Factory{}

func Register(name string, f Factory) {
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("module already registered: %s", name))
	}
	registry[name] = f
}

func New(name string) (Module, error) {
	f, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown module: %s", name)
	}
	return f(), nil
}

func Names() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	return out
}
