module github.com/fqazzazee/netscan-wol

// 1.24 is the floor: crypto/pbkdf2 entered the standard library in that
// release, and the method-and-wildcard ServeMux patterns the API relies on
// arrived in 1.22. Nothing outside the standard library is used.
go 1.24
