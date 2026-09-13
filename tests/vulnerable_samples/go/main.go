package main

import (
	"fmt"
	"os/exec"
)

// Intentionally vulnerable Go sample for Dede tests.
// No real secrets are present.

func runUserCommand(userInput string) {
	// FAKE vulnerability: command injection via shell
	cmd := exec.Command("sh", "-c", userInput)
	out, _ := cmd.CombinedOutput()
	fmt.Println(string(out))
}

func main() {
	runUserCommand("echo hello")
}
