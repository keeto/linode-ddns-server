package ipfilter

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Spec is the YAML form of a policy. It is one of:
//
//   - a policy name, or a single condition that is allowed
//   - a list of conditions, checked in order; "!" in front denies
//   - a list of rules {allow: X} or {deny: X}, where X is a condition, a list
//     of conditions (any may match) or {all: [conditions]}
//
// Both list forms can be mixed.
type Spec struct {
	// Ref names a policy defined elsewhere. Policy is nil when Ref is set.
	Ref    string
	Policy *Policy
}

func (s *Spec) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		v := strings.TrimSpace(n.Value)
		if strings.HasPrefix(v, "!") {
			return lineErr(n, errors.New("a single condition cannot deny; use a list"))
		}
		c, err := parseCond(v)
		if err != nil {
			s.Ref = v // Resolved, or reported as unknown, by the caller.
			return nil
		}
		s.Policy = &Policy{rules: []rule{{allow: true, any: []cond{c}}}}
		return nil
	case yaml.SequenceNode:
		if len(n.Content) == 0 {
			return lineErr(n, errors.New("empty ip policy"))
		}
		p := &Policy{}
		for _, item := range n.Content {
			r, err := parseRule(item)
			if err != nil {
				return lineErr(item, err)
			}
			p.rules = append(p.rules, r)
		}
		s.Policy = p
		return nil
	default:
		return lineErr(n, errors.New("ip policy must be a name, a condition or a list"))
	}
}

func lineErr(n *yaml.Node, err error) error {
	return fmt.Errorf("line %d: %w", n.Line, err)
}

func parseRule(n *yaml.Node) (rule, error) {
	switch n.Kind {
	case yaml.ScalarNode:
		text, deny := strings.CutPrefix(strings.TrimSpace(n.Value), "!")
		c, err := parseCond(text)
		return rule{allow: !deny, any: []cond{c}}, err
	case yaml.MappingNode:
		if len(n.Content) != 2 {
			return rule{}, errors.New("a rule needs exactly one of allow or deny")
		}
		key, val := n.Content[0].Value, n.Content[1]
		if key != "allow" && key != "deny" {
			return rule{}, fmt.Errorf("unknown rule %q: expected allow or deny", key)
		}
		cs, err := parseConds(val)
		return rule{allow: key == "allow", any: cs}, err
	default:
		return rule{}, errors.New("a rule must be a condition or {allow|deny: ...}")
	}
}

// parseConds parses a condition or a list of conditions.
func parseConds(n *yaml.Node) ([]cond, error) {
	if n.Kind != yaml.SequenceNode {
		c, err := parseOne(n)
		return []cond{c}, err
	}
	if len(n.Content) == 0 {
		return nil, errors.New("empty condition list")
	}
	cs := make([]cond, 0, len(n.Content))
	for _, item := range n.Content {
		c, err := parseOne(item)
		if err != nil {
			return nil, err
		}
		cs = append(cs, c)
	}
	return cs, nil
}

// parseOne parses a condition or {all: [conditions]}.
func parseOne(n *yaml.Node) (cond, error) {
	switch {
	case n.Kind == yaml.ScalarNode:
		return parseCond(n.Value)
	case n.Kind == yaml.MappingNode && len(n.Content) == 2 && n.Content[0].Value == "all" &&
		n.Content[1].Kind == yaml.SequenceNode && len(n.Content[1].Content) > 0:
		var cs []cond
		for _, item := range n.Content[1].Content {
			c, err := parseOne(item)
			if err != nil {
				return cond{}, err
			}
			cs = append(cs, c)
		}
		return allOf(cs), nil
	default:
		return cond{}, errors.New("expected a condition or {all: [conditions]}")
	}
}
