package utils

import (
	"log"
	"runtime/debug"
)

// SafeGo runs a function in a goroutine with panic recovery
func SafeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[SafeGo] PANIC in %s: %v\n%s\n", name, r, debug.Stack())
			}
		}()
		fn()
	}()
}
