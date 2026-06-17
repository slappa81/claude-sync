//go:build windows

package util

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileAllAccess is the Windows FILE_ALL_ACCESS access mask, granting full
// control over a file object to the specified SID.
const fileAllAccess = 0x1f01ff

// SecureWriteFile writes data to path and then applies a DACL that grants
// access only to the current user, removing inherited permissions.
// The ACL restriction is best-effort: if it fails the file is still written
// and no error is returned, so callers are not broken in restricted
// environments where ACL manipulation is unavailable.
func SecureWriteFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	// Best-effort: restrict the file to the current user.
	_ = restrictToCurrentUser(path)
	return nil
}

// restrictToCurrentUser sets a DACL on path that allows full access to the
// current process owner and denies all other principals (including inherited
// entries from the parent directory).
func restrictToCurrentUser(path string) error {
	// Obtain the SID of the current process owner.
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	sid := tokenUser.User.Sid

	// Compute ACL buffer size:
	//   ACL header:              unsafe.Sizeof(windows.ACL{}) bytes
	//   ACCESS_ALLOWED_ACE body: ACE_HEADER (4) + Mask (4) + full SID
	sidLen := windows.GetLengthSid(sid)
	aclSize := uint32(unsafe.Sizeof(windows.ACL{})) + 4 + 4 + sidLen

	aclBuf := make([]byte, aclSize)
	acl := (*windows.ACL)(unsafe.Pointer(&aclBuf[0]))

	if err := windows.InitializeAcl(acl, aclSize, windows.ACL_REVISION); err != nil {
		return err
	}
	if err := windows.AddAccessAllowedAce(acl, windows.ACL_REVISION, fileAllAccess, sid); err != nil {
		return err
	}

	// Apply the new DACL.
	// PROTECTED_DACL_SECURITY_INFORMATION (0x80000000) prevents the ACL from
	// inheriting entries from the parent directory, ensuring only the explicit
	// entry above takes effect.
	const protectedDACL = windows.SECURITY_INFORMATION(0x80000000)
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|protectedDACL,
		nil, nil, acl, nil,
	)
}
