// relay-github-verify consumes human-supplied inputs only through stdin.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/reonokiy/openbao-plugin-secrets-relay/provider/githubuat"
)

func main() {
	if run() != 0 {
		os.Exit(1)
	}
}

func run() int {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 65537))
	var input githubuat.VerifyInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err != nil || len(raw) > 65536 || decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		_, _ = os.Stdout.WriteString("{\"passed\":false,\"failed_step\":\"input\"}\n")
		return 1
	}
	interrupted, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(interrupted, 3*time.Minute)
	defer cancel()
	report := githubuat.New().Verify(ctx, input)
	if json.NewEncoder(os.Stdout).Encode(report) != nil || !report.Passed {
		return 1
	}
	return 0
}
