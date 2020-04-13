package com.github.fitosoft.openkloudkrypt.crypto

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions._

class AesCryptoTest {

  @Test
  def testEncryptDecryptString(): Unit = {
    val secret = "8jyrp9aj84wtp985uzpyj98esfp978au5za4t9i9"
    val salt = "98duf9pwh497h8og7ah5"

    val secretText = "Das ist ein Test. Hallo!"
    val coded = AesCrypto.encrypt(secretText, secret, salt)
    val decodedText = AesCrypto.decrypt(coded, secret, salt)

    assertEquals(secretText, decodedText)
  }

  @Test
  def testEncryptDecryptByteArray(): Unit = {
    val secret = "p98auer9hg878jg9gjer97ha8ofv7zah4389u798"
    val salt = "89j9arg98j49jh3458jhs"

    val r = scala.util.Random
    val input: Array[Byte] = r.nextBytes(256)
    val coded: Array[Byte] = AesCrypto.encrypt(input, secret, salt)
    val decoded: Array[Byte] = AesCrypto.decrypt(coded, secret, salt)

    assertArrayEquals(input, decoded)
  }
}
