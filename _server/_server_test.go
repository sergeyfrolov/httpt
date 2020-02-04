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

package main

import (
	"net/http"
	"testing"
)

func TestParseForwarded(t *testing.T) {
	makeHeader := func(headers map[string]string) http.Header {
		h := make(http.Header)
		for k, v := range headers {
			h.Add(k, v)
		}
		return h
	}

	expectErr := func(headersMap map[string]string) {
		header := makeHeader(headersMap)
		h, err := parseForwardedTor(header)
		if err == nil {
			t.Fatalf("Expected: error, got: parsed %s\nheader was: %s\n", h, header)
		}
	}

	expectNoErr := func(headersMap map[string]string, expectedHostname string) {
		header := makeHeader(headersMap)
		h, err := parseForwardedTor(header)
		if err != nil {
			t.Fatalf("Expected: parsed %s, got: error %s\nheader was: %s\n",
				expectedHostname, err, header)
		}

		if h != expectedHostname {
			t.Fatalf("Expected: %s, got: %s\nheader was: %s\n",
				expectedHostname, h, header)
		}
	}

	// according to the rfc, many of those are valid, including 8.8.8.8 and bazinga:123, however
	// tor spec requires that it is an IP address and has port
	expectErr(map[string]string{
		"X-Forwarded-For": "bazinga",
	})
	expectErr(map[string]string{
		"X-Forwarded-For": "bazinga:123",
	})
	expectErr(map[string]string{
		"X-Forwarded-For": "8.8.8.8",
	})
	expectErr(map[string]string{
		"Forwarded": "127.0.0.1",
	})
	expectErr(map[string]string{
		"Forwarded": "127.0.0.1:22",
	})
	expectErr(map[string]string{
		"Forwarded": "for=127.0.0.1",
	})
	expectErr(map[string]string{
		"Forwarded": "for=you:123",
	})
	expectErr(map[string]string{
		"Forwarded": "For=888.8.8.8:123",
	})
	expectErr(map[string]string{
		"Forwarded": "for=[c:d:e:g:h:i]:5678",
	})

	expectNoErr(map[string]string{
		"Forwarded": "for=1.1.1.1:44444",
	}, "1.1.1.1:44444")
	expectNoErr(map[string]string{
		"x-ForwarDed-fOr": "8.8.8.8:123",
	}, "8.8.8.8:123")
	expectNoErr(map[string]string{
		"ForwarDed": "FoR=8.8.8.8:123",
	}, "8.8.8.8:123")
	expectNoErr(map[string]string{
		"ForwarDed": "FoR=[1:2::3:4]:5678",
	}, "[1:2::3:4]:5678")
	expectNoErr(map[string]string{
		"ForwarDed": "FoR=[fe80::1ff:fe23:4567:890a]:5678",
	}, "[fe80::1ff:fe23:4567:890a]:5678")
	expectNoErr(map[string]string{
		"ForwarDed": "FoR=[eeee:eeee:eeee:eeee:eeee:eeee:eeee:eeee]:5678",
	}, "[eeee:eeee:eeee:eeee:eeee:eeee:eeee:eeee]:5678")
	expectNoErr(map[string]string{
		"ForwarDed": "FoR=8.8.8.8:123;",
	}, "8.8.8.8:123")
	expectNoErr(map[string]string{
		"ForwarDed": "FoR=8.8.8.8:123; by=me",
	}, "8.8.8.8:123")
	expectNoErr(map[string]string{
		"ForwarDed": "proto=amazingProto; FoR=8.8.8.8:123; by=me",
	}, "8.8.8.8:123")
	expectNoErr(map[string]string{
		"ForwarDed": "proto=amazingProto;FoR = 8.8.8.8:123 ;by=me",
	}, "8.8.8.8:123")
}
