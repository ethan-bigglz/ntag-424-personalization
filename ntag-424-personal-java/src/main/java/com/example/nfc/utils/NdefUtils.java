package com.example.nfc.utils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class NdefUtils {

    public static final String UID_TAG = "{uid}";
    public static final String COUNTER_TAG = "{counter}";
    public static final String CMAC_TAG = "{cmac}";
    public static final String CMAC_START_TAG = "{cmacStart}";

    public static final String UID_REPLACEMENT = "U".repeat(14);       // 14 bytes
    public static final String COUNTER_REPLACEMENT = "C".repeat(6);    // 6 bytes
    public static final String CMAC_REPLACEMENT = "M".repeat(16);      // 16 bytes

    public static class NdefGenerationResult {
        public byte[] ndef; // Raw file contents: 2-byte length prefix + NDEF message
        public int uidOffset = -1;
        public int sdmReadCtrOffset = -1;
        public int sdmMacOffset = -1;
        public int sdmMacInputOffset = -1;

        @Override
        public String toString() {
            return "NdefGenerationResult{" +
                    "ndefLen=" + (ndef != null ? ndef.length : 0) +
                    ", uidOffset=" + uidOffset +
                    ", sdmReadCtrOffset=" + sdmReadCtrOffset +
                    ", sdmMacOffset=" + sdmMacOffset +
                    ", sdmMacInputOffset=" + sdmMacInputOffset +
                    '}';
        }
    }

    public static NdefGenerationResult generateNDEF(String urlPattern) {
        // Find index of {cmacStart} in the original URL pattern (before replacements)
        int cmacStartIdxInPattern = urlPattern.indexOf(CMAC_START_TAG);

        // Perform tag replacements in the URL pattern
        String replacedUrl = urlPattern
                .replace(UID_TAG, UID_REPLACEMENT)
                .replace(COUNTER_TAG, COUNTER_REPLACEMENT)
                .replace(CMAC_TAG, CMAC_REPLACEMENT);

        // Find index of {cmacStart} in the replaced URL (before removing it)
        int cmacStartIdxInReplaced = replacedUrl.indexOf(CMAC_START_TAG);

        // Remove the {cmacStart} tag from the actual URL to be written
        replacedUrl = replacedUrl.replace(CMAC_START_TAG, "");

        // Encode to NDEF URI Record
        byte[] ndefMessage = encodeNdefUri(replacedUrl);

        // Add 2-byte length prefix (NDEF File Container Format)
        byte[] ndefFileBuffer = new byte[2 + ndefMessage.length];
        ndefFileBuffer[0] = (byte) ((ndefMessage.length >> 8) & 0xFF);
        ndefFileBuffer[1] = (byte) (ndefMessage.length & 0xFF);
        System.arraycopy(ndefMessage, 0, ndefFileBuffer, 2, ndefMessage.length);

        NdefGenerationResult result = new NdefGenerationResult();
        result.ndef = ndefFileBuffer;

        // Find prefix compression details used
        String[] prefixes = {
                "",             // 0x00
                "http://www.",  // 0x01
                "https://www.", // 0x02
                "http://",      // 0x03
                "https://",     // 0x04
        };
        int prefixIndex = 0;
        for (int i = 1; i < prefixes.length; i++) {
            if (replacedUrl.startsWith(prefixes[i])) {
                prefixIndex = i;
                break;
            }
        }
        int prefixLength = prefixes[prefixIndex].length();

        // Calculate offsets inside the NDEF file buffer (which includes the 2-byte length prefix)
        // 2 (length bytes) + 4 (NDEF record header: TNF, TypeLen, PayLen, Type('U')) + 1 (Prefix byte) = 7 bytes
        int baseOffset = 7;

        // Find UID Offset
        int uidIdx = replacedUrl.indexOf(UID_REPLACEMENT);
        if (uidIdx != -1) {
            result.uidOffset = baseOffset + (uidIdx - prefixLength);
            // Overwrite with '0' in ndef file buffer
            byte[] zeros = "0".repeat(UID_REPLACEMENT.length()).getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(zeros, 0, ndefFileBuffer, result.uidOffset, zeros.length);
        }

        // Find Read Counter Offset
        int ctrIdx = replacedUrl.indexOf(COUNTER_REPLACEMENT);
        if (ctrIdx != -1) {
            result.sdmReadCtrOffset = baseOffset + (ctrIdx - prefixLength);
            // Overwrite with '0'
            byte[] zeros = "0".repeat(COUNTER_REPLACEMENT.length()).getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(zeros, 0, ndefFileBuffer, result.sdmReadCtrOffset, zeros.length);
        }

        // Find CMAC Offset
        int cmacIdx = replacedUrl.indexOf(CMAC_REPLACEMENT);
        if (cmacIdx != -1) {
            result.sdmMacOffset = baseOffset + (cmacIdx - prefixLength);
            // Overwrite with '0'
            byte[] zeros = "0".repeat(CMAC_REPLACEMENT.length()).getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(zeros, 0, ndefFileBuffer, result.sdmMacOffset, zeros.length);
        }

        // Calculate SDMMACInputOffset
        if (cmacStartIdxInPattern != -1) {
            result.sdmMacInputOffset = baseOffset + (cmacStartIdxInReplaced - prefixLength);
            // Adjust index down by 1 to match the custom offset logic of the server
            // (Wait, since we removed {cmacStart} after finding index, cmacStartIdxInReplaced will match
            // the offset of the character directly after it. Deducting 1 aligns with the Node.js implementation)
            result.sdmMacInputOffset--;
        } else {
            if (result.sdmMacOffset != -1) {
                result.sdmMacInputOffset = result.sdmMacOffset;
            }
        }

        // Sanity Check: Overlap verification
        if (result.uidOffset != -1 && result.sdmReadCtrOffset != -1) {
            int uidLen = UID_REPLACEMENT.length();
            int ctrLen = COUNTER_REPLACEMENT.length();
            if (!(result.uidOffset >= result.sdmReadCtrOffset + ctrLen ||
                  result.sdmReadCtrOffset >= result.uidOffset + uidLen)) {
                throw new IllegalStateException("UID and counter cannot overlap in the URL.");
            }
        }

        return result;
    }

    public static byte[] encodeNdefUri(String url) {
        String[] prefixes = {
                "",             // 0x00
                "http://www.",  // 0x01
                "https://www.", // 0x02
                "http://",      // 0x03
                "https://",     // 0x04
        };
        int prefixIndex = 0;
        for (int i = 1; i < prefixes.length; i++) {
            if (url.startsWith(prefixes[i])) {
                prefixIndex = i;
                break;
            }
        }
        String remaining = url.substring(prefixes[prefixIndex].length());
        byte[] remainingBytes = remaining.getBytes(StandardCharsets.UTF_8);
        int payloadLength = 1 + remainingBytes.length;

        byte[] record = new byte[4 + payloadLength];
        record[0] = (byte) 0xD1;            // MB=1, ME=1, SR=1, TNF=0x01 (Well-Known)
        record[1] = (byte) 0x01;            // Type Length = 1
        record[2] = (byte) payloadLength;   // Payload Length
        record[3] = (byte) 0x55;            // Type = 'U' (URI Record)
        record[4] = (byte) prefixIndex;     // Prefix Code
        System.arraycopy(remainingBytes, 0, record, 5, remainingBytes.length);

        return record;
    }

    public static int indexOf(byte[] array, byte[] target) {
        if (target.length == 0) return 0;
        outer:
        for (int i = 0; i < array.length - target.length + 1; i++) {
            for (int j = 0; j < target.length; j++) {
                if (array[i + j] != target[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    public static boolean compareNdef(byte[] currentNdef, byte[] newNdef, NdefGenerationResult offsets) {
        byte[] normalizedNdef = Arrays.copyOf(currentNdef, currentNdef.length);

        int uidLen = UID_REPLACEMENT.length();
        int ctrLen = COUNTER_REPLACEMENT.length();
        int macLen = CMAC_REPLACEMENT.length();

        if (offsets.uidOffset != -1 && offsets.uidOffset < normalizedNdef.length) {
            Arrays.fill(normalizedNdef, offsets.uidOffset, Math.min(offsets.uidOffset + uidLen, normalizedNdef.length), (byte) '0');
        }
        if (offsets.sdmReadCtrOffset != -1 && offsets.sdmReadCtrOffset < normalizedNdef.length) {
            Arrays.fill(normalizedNdef, offsets.sdmReadCtrOffset, Math.min(offsets.sdmReadCtrOffset + ctrLen, normalizedNdef.length), (byte) '0');
        }
        if (offsets.sdmMacOffset != -1 && offsets.sdmMacOffset < normalizedNdef.length) {
            Arrays.fill(normalizedNdef, offsets.sdmMacOffset, Math.min(offsets.sdmMacOffset + macLen, normalizedNdef.length), (byte) '0');
        }

        return Arrays.equals(normalizedNdef, newNdef);
    }

    public static String parseNdefUrl(byte[] ndefFileBuffer) {
        try {
            if (ndefFileBuffer == null || ndefFileBuffer.length <= 7) {
                return null;
            }
            int ndefMessageLen = ((ndefFileBuffer[0] & 0xFF) << 8) | (ndefFileBuffer[1] & 0xFF);
            if (ndefMessageLen <= 0 || ndefFileBuffer.length < 2 + ndefMessageLen) {
                return null;
            }
            
            // NDEF record header starts at index 2
            // Byte 4 of ndefFileBuffer is the payload length of the record
            int payloadLen = ndefFileBuffer[4] & 0xFF;
            // Byte 6 is the URI prefix byte (starts of payload)
            int prefixIndex = ndefFileBuffer[6] & 0xFF;
            
            String[] prefixes = {
                    "",             // 0x00
                    "http://www.",  // 0x01
                    "https://www.", // 0x02
                    "http://",      // 0x03
                    "https://",     // 0x04
            };
            String prefix = (prefixIndex >= 0 && prefixIndex < prefixes.length) ? prefixes[prefixIndex] : "";
            
            // Payload length includes prefix byte, so remaining length is payloadLen - 1
            int remainingLen = payloadLen - 1;
            if (remainingLen <= 0 || 7 + remainingLen > ndefFileBuffer.length) {
                return null;
            }
            
            String remaining = new String(ndefFileBuffer, 7, remainingLen, StandardCharsets.UTF_8);
            return prefix + remaining;
        } catch (Exception e) {
            System.err.println("Error parsing NDEF URL: " + e.getMessage());
            return null;
        }
    }
}

