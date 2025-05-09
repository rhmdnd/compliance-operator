// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

import (
	v1 "github.com/openshift/api/config/v1"
)

// UserDefinedMonitoringApplyConfiguration represents a declarative configuration of the UserDefinedMonitoring type for use
// with apply.
type UserDefinedMonitoringApplyConfiguration struct {
	Mode *v1.UserDefinedMode `json:"mode,omitempty"`
}

// UserDefinedMonitoringApplyConfiguration constructs a declarative configuration of the UserDefinedMonitoring type for use with
// apply.
func UserDefinedMonitoring() *UserDefinedMonitoringApplyConfiguration {
	return &UserDefinedMonitoringApplyConfiguration{}
}

// WithMode sets the Mode field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Mode field is set to the value of the last call.
func (b *UserDefinedMonitoringApplyConfiguration) WithMode(value v1.UserDefinedMode) *UserDefinedMonitoringApplyConfiguration {
	b.Mode = &value
	return b
}
