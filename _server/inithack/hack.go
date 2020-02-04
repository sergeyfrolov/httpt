// Copyright 2018 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package inithack

import (
	"os"
	"path"
)

// We need to override CADDYPATH and make sure caddy writes things into TOR_PT_STATE_LOCATION
// as opposed to HOME (which will be something like "/root/" and hardening features rightfully
// prevent PT from writing there). Unfortunately, Caddy uses CADDYPATH in init() functions, which
// run  before than anything in "server" package.
//
// For now, which just set CADDYPATH=TOR_PT_STATE_LOCATION here and import it before caddy.
// https://golang.org/ref/spec#Package_initialization does not guarantee a particular init order,
// which is why we should find an actual fix. TODO!
//
// Potential fixes:
//   1) refactor Caddy: seems like a big patch
//   2) Set CADDYHOME environment variable from Tor: torrc doesn't seem to allow setting arbitrary env vars
//   3) Change Tor behavior to set HOME to TOR_PT_STATE_LOCATION?
//   4) govendor Caddy, and change its source code to import this package, guaranteeing init order
//   5) run Caddy as a separate binary.
func init() {
	if os.Getenv("CADDYPATH") == "" {
		os.Setenv("CADDYPATH", path.Join(os.Getenv("TOR_PT_STATE_LOCATION"), ".caddy"))
	}
}
