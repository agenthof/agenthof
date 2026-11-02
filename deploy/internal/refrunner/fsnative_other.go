//go:build !linux

package refrunner

// CheckNativeFS is a deliberate pass-through off Linux. The bridged-filesystem
// concern (WSL2's 9p /mnt) is Linux-specific, and macOS runs under Seatbelt;
// SMB/NFS socket directories there are a separate, unaddressed question.
func CheckNativeFS(string) error { return nil }
