package com.github.fitosoft.openkloudkrypt.crypto

import java.security._
import java.security.spec.{InvalidKeySpecException, MGF1ParameterSpec, PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.util.Base64
import javax.crypto.{BadPaddingException, Cipher, IllegalBlockSizeException, NoSuchPaddingException}
import javax.crypto.spec.{OAEPParameterSpec, PSource}


object RSAUtil {
  val keyPairGenerator = new RSAKeyPairGenerator

  private val publicKey = Base64.getEncoder.encodeToString(keyPairGenerator.getPublicKey.getEncoded)
  private val privateKey = Base64.getEncoder.encodeToString(keyPairGenerator.getPrivateKey.getEncoded)

  def getPublicKey(base64PublicKey: String): PublicKey = {
    var publicKey: PublicKey = null
    try {
      val keySpec = new X509EncodedKeySpec(Base64.getDecoder.decode(base64PublicKey.getBytes))
      val keyFactory = KeyFactory.getInstance("RSA")
      publicKey = keyFactory.generatePublic(keySpec)
      return publicKey
    } catch {
      case e: NoSuchAlgorithmException =>
        e.printStackTrace()
      case e: InvalidKeySpecException =>
        e.printStackTrace()
    }
    publicKey
  }

  def getPrivateKey(base64PrivateKey: String): PrivateKey = {
    var privateKey: PrivateKey = null
    val keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder.decode(base64PrivateKey.getBytes))
    var keyFactory: KeyFactory = null
    try keyFactory = KeyFactory.getInstance("RSA")
    catch {
      case e: NoSuchAlgorithmException =>
        e.printStackTrace()
    }
    try privateKey = keyFactory.generatePrivate(keySpec)
    catch {
      case e: InvalidKeySpecException =>
        e.printStackTrace()
    }
    privateKey
  }

  @throws[BadPaddingException]
  @throws[IllegalBlockSizeException]
  @throws[InvalidKeyException]
  @throws[NoSuchPaddingException]
  @throws[NoSuchAlgorithmException]
  def encrypt(data: String, publicKey: String): Array[Byte] = {
    val cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
    val oaepParameterSpec = new OAEPParameterSpec("SHA-256", "MGF1",
      MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)
    cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey), oaepParameterSpec)
    cipher.doFinal(data.getBytes)
  }

  @throws[NoSuchPaddingException]
  @throws[NoSuchAlgorithmException]
  @throws[InvalidKeyException]
  @throws[BadPaddingException]
  @throws[IllegalBlockSizeException]
  def decrypt(data: Array[Byte], privateKey: PrivateKey): String = {
    val cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
    val oaepParameterSpec = new OAEPParameterSpec("SHA-256", "MGF1",
      MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)
    cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParameterSpec)
    new String(cipher.doFinal(data))
  }

  @throws[IllegalBlockSizeException]
  @throws[InvalidKeyException]
  @throws[BadPaddingException]
  @throws[NoSuchAlgorithmException]
  @throws[NoSuchPaddingException]
  def decrypt(data: String, base64PrivateKey: String): String = decrypt(Base64.getDecoder.decode(data.getBytes), getPrivateKey(base64PrivateKey))

  @throws[IllegalBlockSizeException]
  @throws[InvalidKeyException]
  @throws[NoSuchPaddingException]
  @throws[BadPaddingException]
  def main(args: Array[String]): Unit = {
    try {
      val encryptedString = Base64.getEncoder.encodeToString(encrypt("This is a great text that is encoded and decoded using a 4096bit RSA key. :)", publicKey))
      System.out.println(encryptedString)
      val decryptedString = RSAUtil.decrypt(encryptedString, privateKey)
      System.out.println(decryptedString)
    } catch {
      case e: NoSuchAlgorithmException =>
        System.err.println(e.getMessage)
    }
  }

  class RSAKeyPairGenerator() {
    private val keyGen: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
    keyGen.initialize(4096)

    private val pair: KeyPair = keyGen.generateKeyPair
    private val privateKey = pair.getPrivate
    private val publicKey = pair.getPublic

    def getPrivateKey: PrivateKey = privateKey

    def getPublicKey: PublicKey = publicKey
  }

}