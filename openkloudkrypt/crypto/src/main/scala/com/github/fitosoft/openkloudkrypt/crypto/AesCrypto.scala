package com.github.fitosoft.openkloudkrypt.crypto

import java.security.spec.KeySpec
import java.util.Base64

import javax.crypto.spec.{IvParameterSpec, PBEKeySpec, SecretKeySpec}
import javax.crypto.{Cipher, SecretKey, SecretKeyFactory}

object AesCrypto {

  private val iv: Array[Byte] = Array(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
  private val iterationCount: Int = 65536
  private val keyLength: Int = 256
  private val defaultEncoding = "UTF-8"

  private def doCrypt(mode: Int, data: Array[Byte], secret: String, salt: String): Array[Byte] = {
    try {
      val ivSpec: IvParameterSpec = new IvParameterSpec(iv)
      val factory: SecretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
      val spec: KeySpec = new PBEKeySpec(secret.toCharArray, salt.getBytes, iterationCount, keyLength)
      val tmp: SecretKey = factory.generateSecret(spec)
      val secretKey: SecretKeySpec = new SecretKeySpec(tmp.getEncoded, "AES")
      val cipher: Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      cipher.init(mode, secretKey, ivSpec)
      cipher.doFinal(data)
    } catch {
      case e: Exception =>
        System.out.println("Error while encrypting: " + e.toString)
        null
    }
  }

  def encrypt(strToEncrypt: String, secret: String, salt: String): String = {
    Base64.getEncoder.encodeToString(encrypt(strToEncrypt.getBytes(defaultEncoding), secret, salt))
  }

  def encrypt(bytesToEncrypt: Array[Byte], secret: String, salt: String): Array[Byte] = {
    doCrypt(Cipher.ENCRYPT_MODE, bytesToEncrypt, secret, salt)
  }

  def decrypt(strToDecrypt: String, secret: String, salt: String): String = {
    new String(decrypt(Base64.getDecoder.decode(strToDecrypt), secret, salt), defaultEncoding)
  }

  def decrypt(bytesToDecrypt: Array[Byte], secret: String, salt: String): Array[Byte] = {
    doCrypt(Cipher.DECRYPT_MODE, bytesToDecrypt, secret, salt)
  }
}
