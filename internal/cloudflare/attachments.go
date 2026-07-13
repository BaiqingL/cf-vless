package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// validateWorkerAttachments inventories Worker features that are not ordinary
// script bindings. Every check is read-only and must pass before a deployment
// can replace the script or removal can delete any remote resource.
func (c *Client) validateWorkerAttachments(ctx context.Context, worker, scriptListOutput string) ([]OperationResult, error) {
	if err := validateWorkerName(worker); err != nil {
		return nil, err
	}
	if err := validateScriptListAttachments(scriptListOutput, worker); err != nil {
		return nil, err
	}

	type check struct {
		args     []string
		validate func(string) error
		label    string
	}
	checks := []check{
		{
			args:     []string{"workers", "scripts", "schedules", "get", "--worker", worker},
			validate: validateEmptySchedules,
			label:    "Worker schedule inventory",
		},
		{
			args:     []string{"workers", "scripts", "settings", "get", "--worker", worker},
			validate: validateScriptSettings,
			label:    "Worker settings inventory",
		},
		{
			args:     []string{"workers", "scripts", "subdomain", "get", "--worker", worker},
			validate: validateDisabledSubdomain,
			label:    "Worker subdomain inventory",
		},
	}

	operations := make([]OperationResult, 0, len(checks))
	for _, check := range checks {
		operation, err := c.execute(ctx, ProviderCF, c.cfWorkerCommand(check.args...), false)
		operations = append(operations, operation)
		if err != nil {
			return operations, err
		}
		if err := check.validate(operation.Stdout); err != nil {
			return operations, fmt.Errorf("decode %s: %w", check.label, err)
		}
	}
	return operations, nil
}

func validateScriptListAttachments(output, worker string) error {
	objects, err := decodeObjectListStrict(output)
	if err != nil {
		return fmt.Errorf("decode Worker script inventory: %w", err)
	}
	var selected map[string]any
	for _, object := range objects {
		if firstString(object, "id", "name", "script_name") != worker {
			continue
		}
		if selected != nil {
			return fmt.Errorf("%w: Worker script inventory is ambiguous", ErrResourceConflict)
		}
		selected = object
	}
	if selected == nil {
		return fmt.Errorf("%w: Worker disappeared from the script inventory", ErrResourceConflict)
	}
	for _, field := range []string{"routes", "tail_consumers"} {
		value, present := selected[field]
		if !present || !emptyNullableList(value) {
			return fmt.Errorf("%w: Worker has an unplanned %s attachment", ErrResourceConflict, field)
		}
	}
	for _, field := range []string{"logpush", "has_assets"} {
		value, present := selected[field]
		disabled, ok := value.(bool)
		if !present || !ok || disabled {
			return fmt.Errorf("%w: Worker has an unplanned or unreadable %s setting", ErrResourceConflict, field)
		}
	}
	return nil
}

func validateEmptySchedules(output string) error {
	root, err := decodeJSONObjectStrict(output)
	if err != nil {
		return err
	}
	value, present := root["schedules"]
	if !present || !emptyList(value) {
		return fmt.Errorf("%w: Worker has an unplanned Cron schedule", ErrResourceConflict)
	}
	return nil
}

func validateScriptSettings(output string) error {
	root, err := decodeJSONObjectStrict(output)
	if err != nil {
		return err
	}
	allowed := map[string]bool{
		"logpush":        true,
		"observability":  true,
		"tags":           true,
		"tail_consumers": true,
	}
	for key := range root {
		if !allowed[key] {
			return fmt.Errorf("%w: Worker settings contain an unplanned field", ErrResourceConflict)
		}
	}
	logpush, present := root["logpush"]
	if enabled, ok := logpush.(bool); !present || !ok || enabled {
		return fmt.Errorf("%w: Worker Logpush state is enabled or unreadable", ErrResourceConflict)
	}
	tailConsumers, present := root["tail_consumers"]
	if !present || !emptyNullableList(tailConsumers) {
		return fmt.Errorf("%w: Worker has an unplanned tail consumer", ErrResourceConflict)
	}
	observability, present := root["observability"]
	if !present || !disabledObservability(observability) {
		return fmt.Errorf("%w: Worker observability state is enabled or unreadable", ErrResourceConflict)
	}
	tags, present := root["tags"]
	if !present || !emptyNullableList(tags) {
		return fmt.Errorf("%w: Worker has an unplanned tag", ErrResourceConflict)
	}
	return nil
}

func validateDisabledSubdomain(output string) error {
	root, err := decodeJSONObjectStrict(output)
	if err != nil {
		return err
	}
	for _, field := range []string{"enabled", "previews_enabled"} {
		value, present := root[field]
		enabled, ok := value.(bool)
		if !present || !ok || enabled {
			return fmt.Errorf("%w: Worker %s state is enabled or unreadable", ErrResourceConflict, field)
		}
	}
	return nil
}

func disabledObservability(value any) bool {
	if value == nil {
		return true
	}
	root, ok := value.(map[string]any)
	if !ok {
		return false
	}
	allowed := map[string]bool{
		"enabled":            true,
		"head_sampling_rate": true,
		"logs":               true,
		"traces":             true,
	}
	for key := range root {
		if !allowed[key] {
			return false
		}
	}
	if enabled, ok := root["enabled"].(bool); !ok || enabled {
		return false
	}
	if sampling, present := root["head_sampling_rate"]; present && !zeroOrNull(sampling) {
		return false
	}
	for _, sectionName := range []string{"logs", "traces"} {
		sectionValue, present := root[sectionName]
		if !present || sectionValue == nil {
			continue
		}
		section, ok := sectionValue.(map[string]any)
		if !ok || !disabledObservabilitySection(section) {
			return false
		}
	}
	return true
}

func disabledObservabilitySection(section map[string]any) bool {
	allowed := map[string]bool{
		"enabled":            true,
		"head_sampling_rate": true,
		"invocation_logs":    true,
		"persist":            true,
	}
	for key := range section {
		if !allowed[key] {
			return false
		}
	}
	if enabled, ok := section["enabled"].(bool); !ok || enabled {
		return false
	}
	for _, field := range []string{"invocation_logs", "persist"} {
		if value, present := section[field]; present {
			enabled, ok := value.(bool)
			if !ok || enabled {
				return false
			}
		}
	}
	if sampling, present := section["head_sampling_rate"]; present && !zeroOrNull(sampling) {
		return false
	}
	return true
}

func zeroOrNull(value any) bool {
	if value == nil {
		return true
	}
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	parsed, err := number.Float64()
	return err == nil && parsed == 0
}

func emptyNullableList(value any) bool {
	return value == nil || emptyList(value)
}

func emptyList(value any) bool {
	items, ok := value.([]any)
	return ok && len(items) == 0
}

func decodeObjectListStrict(output string) ([]map[string]any, error) {
	value, err := decodeJSONStrict(output)
	if err != nil {
		return nil, err
	}
	return objectList(value)
}

func decodeJSONObjectStrict(output string) (map[string]any, error) {
	value, err := decodeJSONStrict(output)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("JSON root is %T, not an object", value)
	}
	return object, nil
}

func decodeJSONStrict(output string) (any, error) {
	decoder := json.NewDecoder(strings.NewReader(output))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("JSON contains trailing values")
		}
		return nil, err
	}
	return value, nil
}
