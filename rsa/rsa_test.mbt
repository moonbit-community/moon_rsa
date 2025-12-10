///|
test "generate_key_pairs" {
  let (publicKey, privateKey) = @rsa.generate_key_pairs(2048, 65537)
  inspect(publicKey.modulus.bit_length(), content="2048")
  inspect(privateKey.modulus.bit_length(), content="2048")
}

///|
test "rsassa_pss_sign" {
  // 生成RSA密钥对
  let (_, privateKey) = @rsa.generate_key_pairs(2048, 65537)

  // 准备测试消息
  let message = Bytes::from_array([b'h', b'e', b'l', b'l', b'o'])

  // 生成签名
  let signature = @rsa.rsassa_pss_sign(privateKey, message)

  // 验证签名长度是否与模数长度一致
  let modulus_len = (privateKey.modulus.bit_length() + 7) / 8
  inspect(signature.length(), content=modulus_len.to_string())

  // 验证签名不为空
  inspect(signature.length() > 0, content="true")
}

///|
test "rsassa_pss_verify_valid_signature" {
  // 生成RSA密钥对
  let (publicKey, privateKey) = @rsa.generate_key_pairs(2048, 65537)

  // 准备测试消息
  let message = Bytes::from_array([b'h', b'e', b'l', b'l', b'o'])

  // 生成签名
  let signature = @rsa.rsassa_pss_sign(privateKey, message)

  // 验证签名
  let is_valid = @rsa.rsassa_pss_verify(publicKey, message, signature)

  // 确认验证通过
  inspect(is_valid, content="true")
}

///|
test "rsassa_pss_verify_invalid_signatures" {
  // 生成两个不同的RSA密钥对
  let (publicKey1, privateKey1) = @rsa.generate_key_pairs(2048, 65537)
  let (publicKey2, _) = @rsa.generate_key_pairs(2048, 65537)

  // 准备测试消息
  let original_message = Bytes::from_array([b'h', b'e', b'l', b'l', b'o'])
  let modified_message = Bytes::from_array([b'h', b'e', b'l', b'l', b'o', b'!'])

  // 生成签名
  let original_signature = @rsa.rsassa_pss_sign(privateKey1, original_message)

  // 测试1: 验证篡改的消息 - 应该失败
  let invalid1 = @rsa.rsassa_pss_verify(
    publicKey1, modified_message, original_signature,
  )
  inspect(invalid1, content="false")

  // 测试2: 验证篡改的签名 - 应该失败
  // 通过修改签名的第一个字节来篡改签名
  if original_signature.length() > 0 {
    let mut corrupted_signature = Bytes::from_array(
      original_signature.to_array(),
    )
    let first_byte = corrupted_signature.at(0)
    corrupted_signature = Bytes::from_array([first_byte ^ 0xFF]) +
      corrupted_signature[1:].to_bytes()
    let invalid2 = @rsa.rsassa_pss_verify(
      publicKey1, original_message, corrupted_signature,
    )
    inspect(invalid2, content="false")
  }

  // 测试3: 使用错误的公钥 - 应该失败
  let invalid3 = @rsa.rsassa_pss_verify(
    publicKey2, original_message, original_signature,
  )
  inspect(invalid3, content="false")
}
