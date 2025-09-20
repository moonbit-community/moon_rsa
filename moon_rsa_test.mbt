
test "generateKeyPairs" {
  let (publicKey, privateKey) = generateKeyPairs(2048, 65537)
}