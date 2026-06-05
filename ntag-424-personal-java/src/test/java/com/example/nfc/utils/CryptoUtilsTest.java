package com.example.nfc.utils;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class CryptoUtilsTest {

    @Test
    public void testCalcSessionKeys() {
        byte[] key = new byte[16]; // All zeros
        byte[] rndA = CryptoUtils.hexToBytes("B98F4C50CF1C2E084FD150E33992B048");
        byte[] rndB = CryptoUtils.hexToBytes("91517975190DCEA6104948EFA3085C1B");

        CryptoUtils.SessionKeys sessionKeys = CryptoUtils.calcSessionKeys(key, rndA, rndB);

        String expectedEnc = "7A93D6571E4B180FCA6AC90C9A7488D4";
        String expectedMac = "FC4AF159B62E549B5812394CAB1918CC";

        assertEquals(expectedEnc, CryptoUtils.bytesToHex(sessionKeys.encKey));
        assertEquals(expectedMac, CryptoUtils.bytesToHex(sessionKeys.macKey));
    }

    @Test
    public void testRotateLeft() {
        byte[] input = CryptoUtils.hexToBytes("1122334455");
        byte[] expected = CryptoUtils.hexToBytes("2233445511");
        assertArrayEquals(expected, CryptoUtils.rotateLeft(input));
    }

    @Test
    public void testRotateRight() {
        byte[] input = CryptoUtils.hexToBytes("1122334455");
        byte[] expected = CryptoUtils.hexToBytes("5511223344");
        assertArrayEquals(expected, CryptoUtils.rotateRight(input));
    }

    @Test
    public void testCustomPaddingEncryptDecrypt() throws Exception {
        byte[] key = new byte[16];
        byte[] data = "Hello, World! Custom Padding Test.".getBytes();
        byte[] iv = new byte[16];

        byte[] encrypted = CryptoUtils.encrypt(key, data, iv);
        byte[] decrypted = CryptoUtils.decrypt(key, encrypted, iv);

        assertArrayEquals(data, decrypted);
    }
}
