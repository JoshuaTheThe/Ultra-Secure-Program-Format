1. Check Magic == \x7fUSPF
2. Verify IntegrityCheck
3. Verify SignSHA (ECDSA, reject if invalid signer)
4. Verify ImageSHA (reject if tampered)
5. If PasswordSHA present, prompt/receive key, verify hash, decrypt
6. Verify each section's SHA256
7. Zero BSS
8. Apply relocations
9. Jump to EntrySymbolIndex