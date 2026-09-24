//go:build !linux
// +build !linux

package main

import "fmt"

func netifdLinkUp(iface, device, v4, v6, gw4, gw6 string) error {
	return fmt.Errorf("netifd interface manager is only supported on Linux")
}

func netifdLinkDown(iface, device string) error {
	return fmt.Errorf("netifd interface manager is only supported on Linux")
}
