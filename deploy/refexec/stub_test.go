package main

// stubFlag is filled in by the hermetic e2e's stub program.
const stubFlag = "-refexec-test-stub"

func runStub([]string) int { return 2 }
