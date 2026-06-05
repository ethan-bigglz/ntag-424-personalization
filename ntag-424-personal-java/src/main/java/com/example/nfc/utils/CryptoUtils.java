package com.example.nfc.utils;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class CryptoUtils {

    private static final int BLOCK_SIZE = 16;
    private static final String CIPHER_ALGORITHM = "AES/CBC/NoPadding";

    // PBKDF2 Key Derivation
    public static byte[] deriveTagKey(byte[] masterKey, byte[] uid, byte keyNo) {
        if (masterKey == null || masterKey.length == 0) {
            throw new IllegalArgumentException("Master key cannot be empty.");
        }
        if (uid == null || uid.length == 0) {
            throw new IllegalArgumentException("UID cannot be empty.");
        }

        // Standard check: if master key is all zeros (factory default test mode)
        boolean allZeros = true;
        for (byte b : masterKey) {
            if (b != 0) {
                allZeros = false;
                break;
            }
        }
        if (masterKey.length == 16 && allZeros) {
            return new byte[16]; // Return all zeros for factory/testing key
        }

        // salt = "key" (3 bytes) + uid + keyNo (1 byte)
        byte[] saltPrefix = "key".getBytes(StandardCharsets.UTF_8);
        byte[] salt = new byte[saltPrefix.length + uid.length + 1];
        System.arraycopy(saltPrefix, 0, salt, 0, saltPrefix.length);
        System.arraycopy(uid, 0, salt, saltPrefix.length, uid.length);
        salt[salt.length - 1] = keyNo;

        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA512Digest());
        generator.init(masterKey, salt, 5000);
        return ((KeyParameter) generator.generateDerivedParameters(128)).getKey(); // 16 bytes (128 bits)
    }

    // AES-128-CBC encryption with custom ISO/IEC 7816-4 padding
    public static byte[] encrypt(byte[] key, byte[] data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        int padLen = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        byte[] paddedData = data;
        if (padLen != BLOCK_SIZE) {
            paddedData = new byte[data.length + padLen];
            System.arraycopy(data, 0, paddedData, 0, data.length);
            paddedData[data.length] = (byte) 0x80; // First byte of padding is 0x80, rest are 0x00 (default java array)
        }

        return cipher.doFinal(paddedData);
    }

    public static byte[] encrypt(byte[] key, byte[] data) throws Exception {
        return encrypt(key, data, new byte[BLOCK_SIZE]);
    }

    // AES-128-CBC decryption with custom ISO/IEC 7816-4 unpadding
    public static byte[] decrypt(byte[] key, byte[] data, byte[] iv) throws Exception {
        if (data.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("Encrypted data length is not a multiple of block size");
        }

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decrypted = cipher.doFinal(data);

        int unpaddedLength = decrypted.length;
        for (int i = decrypted.length - 1; i >= 0; i--) {
            if (decrypted[i] == (byte) 0x80) {
                unpaddedLength = i;
                break;
            }
            if (decrypted[i] != 0x00) {
                return decrypted; // Return as is if invalid padding
            }
        }

        return Arrays.copyOfRange(decrypted, 0, unpaddedLength);
    }

    public static byte[] decrypt(byte[] key, byte[] data) throws Exception {
        return decrypt(key, data, new byte[BLOCK_SIZE]);
    }

    // AES-CMAC
    public static byte[] calculateCmac(byte[] key, byte[] data) {
        CMac cmac = new CMac(new AESEngine());
        cmac.init(new KeyParameter(key));
        cmac.update(data, 0, data.length);
        byte[] out = new byte[cmac.getMacSize()];
        cmac.doFinal(out, 0);
        return out;
    }

    // CMAC truncation (8 bytes from odd indices)
    public static byte[] MACt(byte[] mac) {
        byte[] mact = new byte[8];
        for (int i = 0; i < mac.length; i++) {
            if (i % 2 == 1) {
                mact[i / 2] = mac[i];
            }
        }
        return mact;
    }

    // Rotate left (1 byte offset)
    public static byte[] rotateLeft(byte[] data) {
        if (data == null || data.length <= 1) return data;
        byte[] result = new byte[data.length];
        System.arraycopy(data, 1, result, 0, data.length - 1);
        result[data.length - 1] = data[0];
        return result;
    }

    // Rotate right (1 byte offset)
    public static byte[] rotateRight(byte[] data) {
        if (data == null || data.length <= 1) return data;
        byte[] result = new byte[data.length];
        System.arraycopy(data, 0, result, 1, data.length - 1);
        result[0] = data[data.length - 1];
        return result;
    }

    // Calculate session keys (ENC & MAC)
    public static SessionKeys calcSessionKeys(byte[] key, byte[] rndA, byte[] rndB) {
        byte[] xor = new byte[6];
        for (int i = 0; i < 6; i++) {
            xor[i] = (byte) (rndA[2 + i] ^ rndB[i]);
        }

        // sv1: a5 5a 00 01 00 80 || RndA[0..2] || xor[0..6] || RndB[6..] || RndA[8..]
        byte[] sv1 = new byte[32];
        System.arraycopy(hexToBytes("a55a00010080"), 0, sv1, 0, 6);
        System.arraycopy(rndA, 0, sv1, 6, 2);
        System.arraycopy(xor, 0, sv1, 8, 6);
        System.arraycopy(rndB, 6, sv1, 14, 10);
        System.arraycopy(rndA, 8, sv1, 24, 8);

        // sv2: 5a a5 00 01 00 80 || RndA[0..2] || xor[0..6] || RndB[6..] || RndA[8..]
        byte[] sv2 = new byte[32];
        System.arraycopy(hexToBytes("5aa500010080"), 0, sv2, 0, 6);
        System.arraycopy(rndA, 0, sv2, 6, 2);
        System.arraycopy(xor, 0, sv2, 8, 6);
        System.arraycopy(rndB, 6, sv2, 14, 10);
        System.arraycopy(rndA, 8, sv2, 24, 8);

        byte[] sesAuthENC = calculateCmac(key, sv1);
        byte[] sesAuthMAC = calculateCmac(key, sv2);

        return new SessionKeys(sesAuthENC, sesAuthMAC);
    }

    public static class SessionKeys {
        public final byte[] encKey;
        public final byte[] macKey;

        public SessionKeys(byte[] encKey, byte[] macKey) {
            this.encKey = encKey;
            this.macKey = macKey;
        }
    }

    // Helper for Hex parsing
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
