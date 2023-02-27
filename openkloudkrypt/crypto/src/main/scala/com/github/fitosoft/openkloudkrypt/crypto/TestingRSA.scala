package com.github.fitosoft.openkloudkrypt.crypto

import java.io.{File, FileOutputStream, IOException}
import java.security._

object TestingRSA {

  def main(args: Array[String]): Unit = {
    val keyPairGenerator = new RSAKeyPairGenerator
//    keyPairGenerator.writeToFile("I:\\Users\\Tom\\IdeaProjects\\OpenKloudKrypt\\openkloudkrypt\\crypto\\target/RSA/publicKey", keyPairGenerator.getPublicKey.getEncoded)
//    keyPairGenerator.writeToFile("I:\\Users\\Tom\\IdeaProjects\\OpenKloudKrypt\\openkloudkrypt\\crypto\\target/RSA/privateKey", keyPairGenerator.getPrivateKey.getEncoded)
//    System.out.println(Base64.getEncoder.encodeToString(keyPairGenerator.getPublicKey.getEncoded))
//    System.out.println(Base64.getEncoder.encodeToString(keyPairGenerator.getPrivateKey.getEncoded))
  }

  class RSAKeyPairGenerator() {
    private val keyGen: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
    keyGen.initialize(4096)

    private val pair: KeyPair = keyGen.generateKeyPair
    private val privateKey = pair.getPrivate
    private val publicKey = pair.getPublic

    @throws[IOException]
    def writeToFile(path: String, key: Array[Byte]): Unit = {
      val f = new File(path)
      f.getParentFile.mkdirs
      val fos = new FileOutputStream(f)
      fos.write(key)
      fos.flush()
      fos.close()
    }

    def getPrivateKey: PrivateKey = privateKey

    def getPublicKey: PublicKey = publicKey
  }

}
