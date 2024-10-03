/*
Copyright 2024 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const (
	maxKubernetesResourceNameLength = 253
)

func safeKubernetesNameAppend(name string, suffix string) string {
	dumbAppend := strings.Join([]string{name, suffix}, "-")
	if len(dumbAppend) < maxKubernetesResourceNameLength {
		// if simply appending the suffix isn't too long, just do that
		return dumbAppend
	}

	// We're going to need to remove some of the end of `name` to be able to append `suffix`
	// Take a hash of the full name and add it between `name` and `suffix` so that we don't
	// risk collisions for long names that only differ in the final few characters
	h := sha256.Sum256([]byte(name))

	hashStr := hex.EncodeToString(h[:])[:6]

	// We'll have the form <name>-<hash>-<suffix>
	// Hash is 6 chars long (because we take the last 6 for hashStr below)
	// Suffix is len(suffix) charts long
	// There are two chars for "-" joining characters
	name = name[:len(name)-2-6-len(suffix)]

	return strings.Join([]string{name, hashStr, suffix}, "-")
}
