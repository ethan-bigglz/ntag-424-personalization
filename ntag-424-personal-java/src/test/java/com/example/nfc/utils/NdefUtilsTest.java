package com.example.nfc.utils;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class NdefUtilsTest {

    @Test
    public void testGenerateNdefAndOffsets() {
        String pattern = "https://sdm.nfcdeveloper.com/tagpt?uid={uid}&ctr={counter}&cmac={cmac}";
        NdefUtils.NdefGenerationResult result = NdefUtils.generateNDEF(pattern);

        assertNotNull(result.ndef);
        assertTrue(result.ndef.length > 0);

        // Verify offsets are calculated
        assertNotEquals(-1, result.uidOffset);
        assertNotEquals(-1, result.sdmReadCtrOffset);
        assertNotEquals(-1, result.sdmMacOffset);
        assertNotEquals(-1, result.sdmMacInputOffset);

        // Parse it back to verify URL correctness
        String parsedUrl = NdefUtils.parseNdefUrl(result.ndef);
        
        // Re-construct the replaced URL template for verification (excluding the dummy replacements)
        // Since result.ndef has '0' filled, the parsed URL should contain '0's for placeholders
        String expectedUrl = "https://sdm.nfcdeveloper.com/tagpt?uid=" + "0".repeat(14)
                + "&ctr=" + "0".repeat(6)
                + "&cmac=" + "0".repeat(16);

        assertEquals(expectedUrl, parsedUrl);
    }
}
