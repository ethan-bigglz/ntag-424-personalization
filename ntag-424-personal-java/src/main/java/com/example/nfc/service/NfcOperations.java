package com.example.nfc.service;

import com.example.nfc.utils.CryptoUtils;
import com.example.nfc.utils.NdefUtils;

import javax.smartcardio.*;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.CRC32;

public class NfcOperations {

    private static final byte[] NDEF_AID = CryptoUtils.hexToBytes("D2760000850101");
    private static final byte[] NDEF_FILE_ID = CryptoUtils.hexToBytes("e104");
    private static final byte[] FACTORY_KEY = new byte[16]; // All zeros

    private CardTerminal terminal;
    private Card card;
    private CardChannel channel;
    private int cmdCtr = 0;
    private CommMode commMode = CommMode.PLAIN;
    private final byte[][] keys = new byte[5][16];

    public enum CommMode {
        PLAIN,
        FULL
    }

    public static class PersonalizeResult {
        public final boolean success;
        public final String uid;
        public final String url;
        public final boolean isFactory;
        public final String message;

        public PersonalizeResult(boolean success, String uid, String url, boolean isFactory, String message) {
            this.success = success;
            this.uid = uid;
            this.url = url;
            this.isFactory = isFactory;
            this.message = message;
        }
    }

    public NfcOperations(CardChannel channel) {
        this.channel = channel;
        for (int i = 0; i < 5; i++) {
            System.arraycopy(FACTORY_KEY, 0, this.keys[i], 0, 16);
        }
    }

    public NfcOperations(CardTerminal terminal, Card card) {
        this.terminal = terminal;
        this.card = card;
        this.channel = card.getBasicChannel();
        for (int i = 0; i < 5; i++) {
            System.arraycopy(FACTORY_KEY, 0, this.keys[i], 0, 16);
        }
    }

    public void reconnect() throws Exception {
        if (terminal == null || card == null) {
            throw new IllegalStateException("Cannot reconnect: terminal or card context not provided.");
        }
        System.out.println("Disconnecting and resetting card...");
        card.disconnect(true);
        Thread.sleep(150); // Small delay to allow card reset to settle
        System.out.println("Reconnecting to card...");
        card = terminal.connect("*");
        channel = card.getBasicChannel();
        cmdCtr = 0;
        commMode = CommMode.PLAIN;
    }

    private byte[] send(byte[] cmd, String comment) throws Exception {
        System.out.println((comment != null ? "[" + comment + "] " : "") + "sending: " + CryptoUtils.bytesToHex(cmd));
        CommandAPDU command = new CommandAPDU(cmd);
        ResponseAPDU response = channel.transmit(command);
        byte[] resBytes = response.getBytes();
        System.out.println((comment != null ? "[" + comment + "] " : "") + "received: " + CryptoUtils.bytesToHex(resBytes));
        return resBytes;
    }

    private byte[] wrap(byte CLA, byte INS, byte P1, byte P2, byte[] dataIn) {
        int length = dataIn.length;
        byte[] wrap = new byte[6 + length];
        wrap[0] = CLA;
        wrap[1] = INS;
        wrap[2] = P1;
        wrap[3] = P2;
        wrap[4] = (byte) length;
        System.arraycopy(dataIn, 0, wrap, 5, length);
        wrap[5 + length] = 0x00; // Le = 0
        return wrap;
    }

    // A session context to hold TI, ENC, MAC keys
    public static class SessionContext {
        public byte[] TI;
        public byte[] sesAuthENC;
        public byte[] sesAuthMAC;

        public SessionContext(byte[] TI, byte[] sesAuthENC, byte[] sesAuthMAC) {
            this.TI = TI;
            this.sesAuthENC = sesAuthENC;
            this.sesAuthMAC = sesAuthMAC;
        }
    }

    private byte[] sendFull(SessionContext context, byte INS, byte cmdHeader, byte[] cmdData, String comment) throws Exception {
        // Construct IV: a5 5a || TI (4 bytes) || cmdCtr (2 bytes, LE) || 8 bytes of 0x00
        byte[] IV = new byte[16];
        IV[0] = (byte) 0xa5;
        IV[1] = (byte) 0x5a;
        System.arraycopy(context.TI, 0, IV, 2, 4);
        IV[6] = (byte) (cmdCtr & 0xFF);
        IV[7] = (byte) ((cmdCtr >> 8) & 0xFF);
        // IV[8..15] remain 0x00

        byte[] IVc = CryptoUtils.encrypt(context.sesAuthENC, IV);
        byte[] encryptedCmd = CryptoUtils.encrypt(context.sesAuthENC, cmdData, IVc);

        // macIn: INS || cmdCtr (2 bytes, LE) || TI (4 bytes) || cmdHeader || encryptedCmd
        ByteArrayOutputStream macInStream = new ByteArrayOutputStream();
        macInStream.write(INS);
        macInStream.write(cmdCtr & 0xFF);
        macInStream.write((cmdCtr >> 8) & 0xFF);
        macInStream.write(context.TI);
        macInStream.write(cmdHeader);
        macInStream.write(encryptedCmd);
        byte[] macIn = macInStream.toByteArray();

        byte[] mac = CryptoUtils.calculateCmac(context.sesAuthMAC, macIn);
        byte[] mact = CryptoUtils.MACt(mac);

        // payload: cmdHeader || encryptedCmd || mact
        byte[] payload = new byte[1 + encryptedCmd.length + mact.length];
        payload[0] = cmdHeader;
        System.arraycopy(encryptedCmd, 0, payload, 1, encryptedCmd.length);
        System.arraycopy(mact, 0, payload, 1 + encryptedCmd.length, mact.length);

        byte[] res = send(wrap((byte) 0x90, INS, (byte) 0x00, (byte) 0x00, payload), comment);
        cmdCtr++;

        if (res.length == 2) {
            if (res[1] != 0x00) {
                throw new IllegalStateException("Error in " + comment + ": " + CryptoUtils.bytesToHex(res));
            }
        } else if (res.length == 10) {
            byte[] tMact = Arrays.copyOfRange(res, 0, 8);
            byte responseCode = res[9];
            if (responseCode != 0x00) {
                throw new IllegalStateException("Error response code in " + comment + ": " + responseCode);
            }

            // Verify response MAC
            // rMacInput: 0x00 || cmdCtr (2 bytes, LE) || TI (4 bytes)
            byte[] rMacInput = new byte[7];
            rMacInput[0] = 0x00;
            rMacInput[1] = (byte) (cmdCtr & 0xFF);
            rMacInput[2] = (byte) ((cmdCtr >> 8) & 0xFF);
            System.arraycopy(context.TI, 0, rMacInput, 3, 4);

            byte[] rMac = CryptoUtils.calculateCmac(context.sesAuthMAC, rMacInput);
            byte[] rMact = CryptoUtils.MACt(rMac);

            if (!Arrays.equals(rMact, tMact)) {
                throw new IllegalStateException("Response MAC verification failed in " + comment);
            }
        } else {
            System.out.println("Response contained unexpected data length (" + res.length + "), returning anyway");
        }

        return res;
    }

    public byte[] getUid() throws Exception {
        byte[] res = send(new byte[]{(byte) 0xFF, (byte) 0xCA, 0x00, 0x00, 0x00}, "get uid");
        if (res.length < 2 || res[res.length - 1] != 0x00) {
            throw new IllegalStateException("Error getting UID: " + CryptoUtils.bytesToHex(res));
        }
        return Arrays.copyOfRange(res, 0, res.length - 2);
    }

    public SessionContext authenticate(Object keyNoObj) throws Exception {
        byte keyNo;
        byte[] key;
        boolean isFactory = false;

        if (keyNoObj instanceof String && "factory".equals(keyNoObj)) {
            keyNo = 0;
            key = FACTORY_KEY;
            isFactory = true;
        } else if (keyNoObj instanceof Number) {
            keyNo = ((Number) keyNoObj).byteValue();
            key = this.keys[keyNo];
        } else {
            throw new IllegalArgumentException("Invalid key number format");
        }

        byte[] res1 = send(wrap((byte) 0x90, (byte) 0x71, (byte) 0x00, (byte) 0x00, new byte[]{keyNo, 0x00}), "authenticate");
        if (res1[res1.length - 1] != (byte) 0xaf) {
            throw new IllegalStateException("Authentication Part 1 failed: NTAG status is not AF. Response: " + CryptoUtils.bytesToHex(res1));
        }

        byte[] ecRndB = Arrays.copyOfRange(res1, 0, res1.length - 2);
        byte[] RndB = CryptoUtils.decrypt(key, ecRndB);
        byte[] RndBp = CryptoUtils.rotateLeft(RndB);

        // Generate RndA
        byte[] RndA = new byte[16];
        new SecureRandom().nextBytes(RndA);

        // msg = RndA || RndBp
        byte[] msg = new byte[32];
        System.arraycopy(RndA, 0, msg, 0, 16);
        System.arraycopy(RndBp, 0, msg, 16, 16);

        byte[] encMsg = CryptoUtils.encrypt(key, msg);
        byte[] res2 = send(wrap((byte) 0x90, (byte) 0xaf, (byte) 0x00, (byte) 0x00, encMsg), "set up RndA");

        if (res2[res2.length - 1] != 0x00) {
            throw new IllegalStateException("Authentication Part 2 failed: NTAG status is not 00. Response: " + CryptoUtils.bytesToHex(res2));
        }

        byte[] ecRndAp = Arrays.copyOfRange(res2, 0, res2.length - 2);
        byte[] TiRndAPDcap2PCDcap2 = CryptoUtils.decrypt(key, ecRndAp);

        byte[] TI = Arrays.copyOfRange(TiRndAPDcap2PCDcap2, 0, 4);
        byte[] RndAp = Arrays.copyOfRange(TiRndAPDcap2PCDcap2, 4, 20);

        // Compare RndA2 with RndA
        byte[] RndA2 = CryptoUtils.rotateRight(RndAp);
        if (!Arrays.equals(RndA, RndA2)) {
            throw new IllegalStateException("Authentication failed: Random bytes RndA mismatch");
        }

        cmdCtr = 0;
        commMode = CommMode.FULL;
        System.out.println("Successfully authenticated using key " + keyNo + (isFactory ? " (factory)" : ""));

        CryptoUtils.SessionKeys sKeys = CryptoUtils.calcSessionKeys(key, RndA, RndB);
        return new SessionContext(TI, sKeys.encKey, sKeys.macKey);
    }

    public static int calculateJamCrc(byte[] data) {
        CRC32 crc = new CRC32();
        crc.update(data);
        return (int) (~crc.getValue() & 0xFFFFFFFFL);
    }

    public void changeKey(byte keyNo, byte[] newKey, SessionContext context) throws Exception {
        byte INS = (byte) 0xc4;
        byte[] oldKey = FACTORY_KEY;
        byte newKeyVersion = 0x01;
        byte[] keyData = new byte[32];

        if (keyNo == 0) {
            System.arraycopy(newKey, 0, keyData, 0, 16);
            keyData[16] = newKeyVersion;
            keyData[17] = (byte) 0x80;
            // The rest is 0x00
        } else {
            byte[] keyXor = new byte[16];
            for (int i = 0; i < 16; i++) {
                keyXor[i] = (byte) (newKey[i] ^ oldKey[i]);
            }
            int crc32 = calculateJamCrc(newKey);

            System.arraycopy(keyXor, 0, keyData, 0, 16);
            keyData[16] = newKeyVersion;
            // Bytes 17..20: CRC32 in Little Endian
            keyData[17] = (byte) (crc32 & 0xFF);
            keyData[18] = (byte) ((crc32 >> 8) & 0xFF);
            keyData[19] = (byte) ((crc32 >> 16) & 0xFF);
            keyData[20] = (byte) ((crc32 >> 24) & 0xFF);
            keyData[21] = (byte) 0x80;
            // The rest is 0x00
        }

        if (commMode == CommMode.FULL) {
            sendFull(context, INS, keyNo, keyData, "changeKey");
        } else {
            throw new IllegalStateException("Must be authenticated in CommMode.FULL to change keys.");
        }
    }

    public byte[] getFileSettings() throws Exception {
        byte[] res = send(wrap((byte) 0x90, (byte) 0xf5, (byte) 0x00, (byte) 0x00, new byte[]{0x02}), "get file settings");
        if (res[res.length - 1] != 0x00) {
            throw new IllegalStateException("Error getting file settings: " + CryptoUtils.bytesToHex(res));
        }
        return Arrays.copyOfRange(res, 0, res.length - 2);
    }

    public void setFileSettings(byte[] cmdData, SessionContext context) throws Exception {
        byte cmd = (byte) 0x5f;
        byte fileNo = 0x02;

        if (commMode == CommMode.FULL) {
            sendFull(context, cmd, fileNo, cmdData, "setFileSettings (Authenticated)");
        } else {
            byte[] settings = new byte[1 + cmdData.length];
            settings[0] = fileNo;
            System.arraycopy(cmdData, 0, settings, 1, cmdData.length);
            byte[] res = send(wrap((byte) 0x90, cmd, (byte) 0x00, (byte) 0x00, settings), "set file settings (Plain)");
            if (res[res.length - 1] != 0x00) {
                throw new IllegalStateException("Error setting file settings: " + CryptoUtils.bytesToHex(res));
            }
        }
    }

    public void setFileSettings(byte[] cmdData) throws Exception {
        setFileSettings(cmdData, null);
    }

    public void writeNdef(byte[] ndef) throws Exception {
        // Select file
        byte[] res = send(wrap((byte) 0x00, (byte) 0xa4, (byte) 0x00, (byte) 0x0c, NDEF_FILE_ID), "select file");
        if (res[res.length - 1] != 0x00) {
            throw new IllegalStateException("Select file failed: " + CryptoUtils.bytesToHex(res));
        }

        // write ndef via update binary: CLA=0x00, INS=0xD6, P1=0x00, P2=0x00, Lc=ndef.length, data=ndef
        byte[] cmd = new byte[5 + ndef.length];
        cmd[0] = 0x00;
        cmd[1] = (byte) 0xd6;
        cmd[2] = 0x00;
        cmd[3] = 0x00;
        cmd[4] = (byte) ndef.length;
        System.arraycopy(ndef, 0, cmd, 5, ndef.length);

        res = send(cmd, "write ndef");
        if (res[res.length - 1] != 0x00) {
            throw new IllegalStateException("Write NDEF failed: " + CryptoUtils.bytesToHex(res));
        }
    }

    public byte[] readNdef() throws Exception {
        // Select file
        byte[] res = send(wrap((byte) 0x00, (byte) 0xa4, (byte) 0x00, (byte) 0x0c, NDEF_FILE_ID), "select file");
        if (res[res.length - 1] != 0x00) {
            throw new IllegalStateException("Select file failed: " + CryptoUtils.bytesToHex(res));
        }

        // read binary: CLA=0x00, INS=0xB0, P1=0x00, P2=0x00, Le=0x80
        byte[] cmd = new byte[]{0x00, (byte) 0xb0, 0x00, 0x00, (byte) 0x80};
        res = send(cmd, "read ndef");
        if (res[res.length - 1] != 0x00) {
            throw new IllegalStateException("Read NDEF failed: " + CryptoUtils.bytesToHex(res));
        }

        // Read the length (first 2 bytes, Big Endian)
        int length = ((res[0] & 0xFF) << 8) | (res[1] & 0xFF);
        // Return 2 length bytes + actual ndef message length
        return Arrays.copyOfRange(res, 0, 2 + length);
    }

    public static boolean isFactorySettings(byte[] settings) {
        byte[] factorySettings = CryptoUtils.hexToBytes("0000e0ee000100");
        return Arrays.equals(settings, factorySettings);
    }

    public static boolean compareFileSettings(byte[] currentSettings, byte[] newSettings) {
        // Omit FileType (index 0) and compare options and rights
        // Node.js:
        // currentSettings.slice(1, 4) matches newSettings.slice(0, 3)
        // and currentSettings.slice(7) matches newSettings.slice(3)
        byte[] currentNormalized = new byte[3 + (currentSettings.length - 7)];
        System.arraycopy(currentSettings, 1, currentNormalized, 0, 3);
        System.arraycopy(currentSettings, 7, currentNormalized, 3, currentSettings.length - 7);

        return Arrays.equals(currentNormalized, newSettings);
    }

    public static byte[] generateFileSettings(NdefUtils.NdefGenerationResult offsets, FileAccessRights fileAR, SdmAccessRights sdmAR) {
        // Defaults if null
        if (fileAR == null) fileAR = new FileAccessRights((byte)0x0e, (byte)0x0e, (byte)0x0e, (byte)0x0e);
        if (sdmAR == null) sdmAR = new SdmAccessRights((byte)0x0e, (byte)0x00, (byte)0x0f);

        byte[] cmdData = new byte[6];

        byte fileOption = 0x00;
        if (offsets.uidOffset != -1 || offsets.sdmReadCtrOffset != -1 || offsets.sdmMacInputOffset != -1 || offsets.sdmMacOffset != -1) {
            fileOption = (byte) (fileOption | 0x40); // Enable SDM
        }

        byte sdmOptions = 0x00;
        if ((fileOption & 0x40) == 0x40) {
            if (offsets.uidOffset != -1) sdmOptions = (byte) (sdmOptions | 0x80);
            if (offsets.sdmReadCtrOffset != -1) sdmOptions = (byte) (sdmOptions | 0x40);
            sdmOptions = (byte) (sdmOptions | 0x01); // Use MAC
        }

        int accessRights = (fileAR.read << 12) | (fileAR.write << 8) | (fileAR.readWrite << 4) | fileAR.change;
        int sdmAccessRights = (sdmAR.sdmMetaRead << 12) | (sdmAR.sdmFileRead << 8) | (0x0f << 4) | sdmAR.sdmCtrRet;

        cmdData[0] = fileOption;
        cmdData[1] = (byte) (accessRights & 0xFF);
        cmdData[2] = (byte) ((accessRights >> 8) & 0xFF);
        cmdData[3] = sdmOptions;
        cmdData[4] = (byte) (sdmAccessRights & 0xFF);
        cmdData[5] = (byte) ((sdmAccessRights >> 8) & 0xFF);

        // Concatenate variable length fields based on options
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(cmdData);

            if ((sdmOptions & 0x80) == 0x80 && sdmAR.sdmMetaRead == (byte) 0x0e) {
                bos.write(intTo3Bytes(offsets.uidOffset));
            }
            if ((sdmOptions & 0x40) == 0x40 && sdmAR.sdmMetaRead == (byte) 0x0e) {
                bos.write(intTo3Bytes(offsets.sdmReadCtrOffset));
            }
            if (sdmAR.sdmFileRead != (byte) 0x0f) {
                bos.write(intTo3Bytes(offsets.sdmMacInputOffset));
            }
            if (sdmAR.sdmFileRead != (byte) 0x0f) {
                bos.write(intTo3Bytes(offsets.sdmMacOffset));
            }
            return bos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] intTo3Bytes(int val) {
        byte[] bytes = new byte[3];
        bytes[0] = (byte) (val & 0xFF);
        bytes[1] = (byte) ((val >> 8) & 0xFF);
        bytes[2] = (byte) ((val >> 16) & 0xFF);
        return bytes;
    }

    public static class FileAccessRights {
        public byte read;
        public byte write;
        public byte readWrite;
        public byte change;

        public FileAccessRights(byte read, byte write, byte readWrite, byte change) {
            this.read = read;
            this.write = write;
            this.readWrite = readWrite;
            this.change = change;
        }

        public static FileAccessRights parse(String r, String w, String rw, String c) {
            return new FileAccessRights(
                    (byte) Integer.parseInt(r, 16),
                    (byte) Integer.parseInt(w, 16),
                    (byte) Integer.parseInt(rw, 16),
                    (byte) Integer.parseInt(c, 16)
            );
        }
    }

    public static class SdmAccessRights {
        public byte sdmMetaRead;
        public byte sdmFileRead;
        public byte sdmCtrRet;

        public SdmAccessRights(byte sdmMetaRead, byte sdmFileRead, byte sdmCtrRet) {
            this.sdmMetaRead = sdmMetaRead;
            this.sdmFileRead = sdmFileRead;
            this.sdmCtrRet = sdmCtrRet;
        }

        public static SdmAccessRights parse(String mr, String fr, String cr) {
            return new SdmAccessRights(
                    (byte) Integer.parseInt(mr, 16),
                    (byte) Integer.parseInt(fr, 16),
                    (byte) Integer.parseInt(cr, 16)
            );
        }
    }

    // Fully personalization routine
    public PersonalizeResult personalize(byte[] masterKey, String url) throws Exception {
        try {
            // 1. Get UID
            byte[] UID = getUid();
            String uidHex = CryptoUtils.bytesToHex(UID);

            // 2. Derive keys
            for (byte i = 0; i < 5; i++) {
                this.keys[i] = CryptoUtils.deriveTagKey(masterKey, UID, i);
            }

            // 3. Select app
            byte[] res = send(wrap((byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x0c, NDEF_AID), "select app");
            if (res[res.length - 1] != 0x00) {
                throw new IllegalStateException("App selection failed: " + CryptoUtils.bytesToHex(res));
            }

            // 4. Get current settings
            byte[] fileSettings = getFileSettings();
            boolean isFactory = isFactorySettings(fileSettings);

            // 5. Generate new NDEF message
            NdefUtils.NdefGenerationResult ndefGen = NdefUtils.generateNDEF(url);

            // 6. Compare NDEF to check if write is needed
            byte[] currentNdef = readNdef();
            boolean ndefNeedsUpdate = !NdefUtils.compareNdef(currentNdef, ndefGen.ndef, ndefGen);

            // 7. Generate new settings and lock down
            FileAccessRights lockFileAR = new FileAccessRights((byte)0x0e, (byte)0x00, (byte)0x00, (byte)0x00); // Read Free, Write/Change Key 0
            SdmAccessRights lockSdmAR = new SdmAccessRights((byte)0x0e, (byte)0x00, (byte)0x0f); // Meta Free, FileRead Key 0, CtrRet Denied
            byte[] newSettings = generateFileSettings(ndefGen, lockFileAR, lockSdmAR);

            SessionContext auth = null;

            if (isFactory) {
                // Factory tag path
                if (ndefNeedsUpdate) {
                    // Write NDEF using free write access (factory defaults have free write access)
                    // Must be done before authenticating to prevent 6982 session security errors
                    writeNdef(ndefGen.ndef);
                }

                auth = authenticate("factory");
                changeKey((byte) 0, this.keys[0], auth);
                auth = authenticate(0);

                for (byte i = 1; i < 5; i++) {
                    changeKey(i, this.keys[i], auth);
                }
                System.out.println("Diversified keys updated");

                // Set file settings
                byte[] exampleFileSettings = CryptoUtils.hexToBytes("40EEEEC1F121200000430000430000");
                if (commMode != CommMode.FULL) {
                    auth = authenticate(0);
                }
                setFileSettings(exampleFileSettings, auth);
                commMode = CommMode.PLAIN; // Reset to plain mode
                setFileSettings(newSettings);
            } else {
                // Already personalized tag path (re-personalization or fixing NDEF)
                int accessRights = ((fileSettings[3] & 0xFF) << 8) | (fileSettings[2] & 0xFF);
                int changeKeyNo = accessRights & 0x000F;

                if (ndefNeedsUpdate) {
                    System.out.println("NDEF needs update. Re-personalizing tag...");
                    // 1. Authenticate with Key 0 (Change File Settings & NDEF Write key)
                    auth = authenticate(0);

                    // 2. Temporarily unlock file settings (keep SDM enabled, but disable features/offsets to bypass 919E validation)
                    // We must keep SDM enabled (0x40) as it is read-only and cannot be disabled (0x00) once turned on.
                    byte[] exampleFileSettings = CryptoUtils.hexToBytes("40EEEE00FFFF");
                    setFileSettings(exampleFileSettings, auth);

                    // 3. Reconnect to close the authenticated session and enter plain mode
                    reconnect();

                    // 4. Select NDEF App (since card reset cleared the app selection)
                    byte[] selectAppRes = send(wrap((byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x0c, NDEF_AID), "select app after reset");
                    if (selectAppRes[selectAppRes.length - 1] != 0x00) {
                        throw new IllegalStateException("App selection after reset failed: " + CryptoUtils.bytesToHex(selectAppRes));
                    }

                    // 5. Write NDEF URL (now in plain mode since card was reset and NDEF write is FREE)
                    writeNdef(ndefGen.ndef);

                    // 6. Lock settings back to newSettings (since change right is FREE, we can write settings in plain mode)
                    setFileSettings(newSettings);
                } else if (!compareFileSettings(fileSettings, newSettings)) {
                    // NDEF is OK, but settings mismatch
                    if (changeKeyNo != 0x0E && commMode != CommMode.FULL) {
                        auth = authenticate(changeKeyNo);
                    }
                    setFileSettings(newSettings, auth);
                }
            }

            return new PersonalizeResult(
                    true,
                    uidHex,
                    url,
                    isFactory,
                    isFactory ? "Tag personalized with new diversified keys and settings" : "Tag updated with new settings"
            );
        } catch (Exception e) {
            System.err.println("Error personalizing tag: " + e.getMessage());
            throw e;
        }
    }
}
