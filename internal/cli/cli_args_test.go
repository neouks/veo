package cli

import (
	"reflect"
	"testing"
)

func TestBuildHostAllowList(t *testing.T) {
	t.Parallel()

	targets := []string{
		"*.baidu.com",
		"https://*.baidu.com/admin",
		"10.0.0.*",
		"https://api.example.com:8443/path?q=1",
	}

	got := buildHostAllowList(targets)
	want := []string{
		"*.baidu.com",
		"10.0.0.*",
		"api.example.com",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildHostAllowList() = %#v, want %#v", got, want)
	}
}
