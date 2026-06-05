package com.example.nfc.controller;

import com.example.nfc.entity.NfcItemMapping;
import com.example.nfc.repository.NfcItemMappingRepository;
import com.example.nfc.service.NfcOperations;
import com.example.nfc.utils.CryptoUtils;
import com.example.nfc.utils.NdefUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import javax.smartcardio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;

@RestController
public class NfcController {

    private final ReentrantLock nfcLock = new ReentrantLock();

    @Autowired
    private NfcItemMappingRepository mappingRepository;

    @Value("${nfc.master-key-hex}")
    private String masterKeyHex;

    @Value("${nfc.reader-name}")
    private String readerNamePattern;

    // Helper for short 16-bit LE read
    private static int readUInt16LE(byte[] data, int offset) {
        return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
    }

    // Helper for 24-bit LE read
    private static int readUInt24LE(byte[] data, int offset) {
        return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8) | ((data[offset + 2] & 0xFF) << 16);
    }

    private static String toHexChar(int value) {
        return String.format("%x", value & 0x0F);
    }

    public static class FileAR {
        public String read;
        public String write;
        public String readWrite;
        public String change;

        public FileAR(String read, String write, String readWrite, String change) {
            this.read = read;
            this.write = write;
            this.readWrite = readWrite;
            this.change = change;
        }
    }

    public static class SdmAR {
        public String sdmMetaRead;
        public String sdmFileRead;
        public String sdmCtrRet;

        public SdmAR(String sdmMetaRead, String sdmFileRead, String sdmCtrRet) {
            this.sdmMetaRead = sdmMetaRead;
            this.sdmFileRead = sdmFileRead;
            this.sdmCtrRet = sdmCtrRet;
        }
    }

    public static class ParsedSettings {
        public int fileType;
        public int fileOption;
        public int accessRights;
        public FileAR fileAR;
        public int fileSize;
        public Integer sdmOptions;
        public Integer sdmAccessRights;
        public SdmAR sdmAR;
        public Integer uidOffset;
        public Integer sdmReadCtrOffset;
        public Integer sdmMacInputOffset;
        public Integer sdmMacOffset;
    }

    private ParsedSettings parseSettings(byte[] settings) {
        ParsedSettings parsed = new ParsedSettings();
        int index = 0;
        parsed.fileType = settings[index++] & 0xFF;
        parsed.fileOption = settings[index++] & 0xFF;
        
        parsed.accessRights = readUInt16LE(settings, index);
        parsed.fileAR = new FileAR(
                toHexChar((parsed.accessRights & 0xf000) >> 12),
                toHexChar((parsed.accessRights & 0x0f00) >> 8),
                toHexChar((parsed.accessRights & 0x00f0) >> 4),
                toHexChar(parsed.accessRights & 0x000f)
        );
        index += 2;

        parsed.fileSize = readUInt24LE(settings, index);
        index += 3;

        if ((parsed.fileOption & 0x40) == 0x40) {
            parsed.sdmOptions = settings[index++] & 0xFF;
            parsed.sdmAccessRights = readUInt16LE(settings, index);
            parsed.sdmAR = new SdmAR(
                    toHexChar((parsed.sdmAccessRights & 0xf000) >> 12),
                    toHexChar((parsed.sdmAccessRights & 0x0f00) >> 8),
                    toHexChar(parsed.sdmAccessRights & 0x000f)
            );
            index += 2;
        }

        List<Integer> values = new ArrayList<>();
        while (index < settings.length) {
            if (index + 3 <= settings.length) {
                values.add(readUInt24LE(settings, index));
                index += 3;
            } else {
                break;
            }
        }

        if (!values.isEmpty()) {
            int valIdx = 0;
            if ((parsed.sdmOptions & 0x80) == 0x80 && "e".equals(parsed.sdmAR.sdmMetaRead)) {
                if (valIdx < values.size()) parsed.uidOffset = values.get(valIdx++);
            }
            if ((parsed.sdmOptions & 0x40) == 0x40 && "e".equals(parsed.sdmAR.sdmMetaRead)) {
                if (valIdx < values.size()) parsed.sdmReadCtrOffset = values.get(valIdx++);
            }
            if (!"f".equals(parsed.sdmAR.sdmFileRead)) {
                if (valIdx < values.size()) parsed.sdmMacInputOffset = values.get(valIdx++);
            }
            if (!"f".equals(parsed.sdmAR.sdmFileRead)) {
                if (valIdx < values.size()) parsed.sdmMacOffset = values.get(valIdx++);
            }
        }

        return parsed;
    }

    private CardTerminal getTerminal() throws CardException {
        TerminalFactory factory = TerminalFactory.getDefault();
        CardTerminals terminals = factory.terminals();
        List<CardTerminal> list = terminals.list();
        if (list.isEmpty()) {
            return null;
        }
        if (readerNamePattern == null || readerNamePattern.isBlank()) {
            return list.get(0);
        }
        for (CardTerminal t : list) {
            if (t.getName().toLowerCase().contains(readerNamePattern.toLowerCase())) {
                return t;
            }
        }
        return null;
    }

    @GetMapping("/status")
    public ResponseEntity<?> getStatus() {
        try {
            CardTerminal terminal = getTerminal();
            boolean isReady = terminal != null;
            byte[] masterKey = CryptoUtils.hexToBytes(masterKeyHex);
            boolean isSecure = false;
            if (masterKey.length == 16) {
                for (byte b : masterKey) {
                    if (b != 0) {
                        isSecure = true;
                        break;
                    }
                }
            }

            Map<String, Object> status = new HashMap<>();
            status.put("isReaderReady", isReady);
            status.put("reader", isReady ? terminal.getName() : null);
            status.put("lastError", null);
            status.put("masterKeyConfigured", masterKey.length == 16);
            status.put("masterKeyIsSecure", isSecure);
            status.put("readerConfigured", readerNamePattern != null && !readerNamePattern.isBlank());

            return ResponseEntity.ok(status);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/card/uid")
    public ResponseEntity<?> getCardUid() {
        nfcLock.lock();
        try {
            CardTerminal terminal = getTerminal();
            if (terminal == null) {
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("error", "NFC reader not ready"));
            }
            if (!terminal.isCardPresent()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "No card detected"));
            }

            Card card = terminal.connect("*");
            CardChannel channel = card.getBasicChannel();
            NfcOperations nfcOps = new NfcOperations(channel);
            byte[] uidBytes = nfcOps.getUid();
            String uidHex = CryptoUtils.bytesToHex(uidBytes);

            return ResponseEntity.ok(Map.of("uid", uidHex));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        } finally {
            nfcLock.unlock();
        }
    }

    @GetMapping("/card/settings")
    public ResponseEntity<?> getCardSettings() {
        nfcLock.lock();
        try {
            CardTerminal terminal = getTerminal();
            if (terminal == null) {
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("error", "NFC reader not ready"));
            }
            if (!terminal.isCardPresent()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "No card detected"));
            }

            Card card = terminal.connect("*");
            CardChannel channel = card.getBasicChannel();
            NfcOperations nfcOps = new NfcOperations(channel);

            // Select app (ISO SELECT BY DF NAME)
            byte[] selectAppCmd = new byte[]{
                    0x00, (byte) 0xa4, 0x04, 0x0c, 0x07,
                    (byte) 0xD2, (byte) 0x76, 0x00, 0x00, (byte) 0x85, 0x01, 0x01, 0x00
            };
            channel.transmit(new CommandAPDU(selectAppCmd));

            byte[] settings = nfcOps.getFileSettings();
            ParsedSettings parsed = parseSettings(settings);

            Map<String, Object> response = new HashMap<>();
            response.put("raw", CryptoUtils.bytesToHex(settings));
            response.put("parsed", parsed);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        } finally {
            nfcLock.unlock();
        }
    }

    @GetMapping("/card/read")
    public ResponseEntity<?> readCard() {
        nfcLock.lock();
        try {
            CardTerminal terminal = getTerminal();
            if (terminal == null) {
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("error", "NFC reader not ready"));
            }
            if (!terminal.isCardPresent()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "No card detected"));
            }

            Card card = terminal.connect("*");
            CardChannel channel = card.getBasicChannel();
            NfcOperations nfcOps = new NfcOperations(channel);

            String uidHex = CryptoUtils.bytesToHex(nfcOps.getUid());

            // Select NDEF Application (ISO SELECT BY DF NAME)
            byte[] selectAppCmd = new byte[]{
                    0x00, (byte) 0xa4, 0x04, 0x0c, 0x07,
                    (byte) 0xD2, (byte) 0x76, 0x00, 0x00, (byte) 0x85, 0x01, 0x01, 0x00
            };
            channel.transmit(new CommandAPDU(selectAppCmd));

            byte[] ndef = nfcOps.readNdef();
            String ndefUrl = NdefUtils.parseNdefUrl(ndef);

            byte[] settings = nfcOps.getFileSettings();
            ParsedSettings parsed = parseSettings(settings);

            Map<String, Object> response = new HashMap<>();
            response.put("uid", uidHex);
            response.put("url", ndefUrl);
            response.put("ndefRaw", CryptoUtils.bytesToHex(ndef));
            response.put("settings", parsed);

            if (ndefUrl == null) {
                response.put("warning", "No URL found in NDEF message");
            }

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        } finally {
            nfcLock.unlock();
        }
    }

    @PostMapping("/card/personalize")
    public ResponseEntity<?> personalizeCard(@RequestBody Map<String, String> body) {
        nfcLock.lock();
        try {
            CardTerminal terminal = getTerminal();
            if (terminal == null) {
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("error", "NFC reader not ready"));
            }
            if (!terminal.isCardPresent()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "No card detected"));
            }

            String url = body.get("url");
            if (url == null || url.isBlank()) {
                String baseUrl = body.getOrDefault("baseUrl", "https://sdm.nfcdeveloper.com");
                url = baseUrl + "/tagpt?uid={uid}&ctr={counter}&cmac={cmac}";
            }

            if (masterKeyHex == null || masterKeyHex.isBlank()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "Master key not configured"));
            }

            byte[] masterKey = CryptoUtils.hexToBytes(masterKeyHex);

            // Extract item_cd query parameter if present
            String itemCd = null;
            try {
                itemCd = UriComponentsBuilder.fromUriString(url)
                        .build()
                        .getQueryParams()
                        .getFirst("item_cd");
            } catch (Exception e) {
                System.err.println("Could not parse URL query parameters: " + e.getMessage());
            }

            Card card = terminal.connect("*");
            NfcOperations nfcOps = new NfcOperations(terminal, card);

            NfcOperations.PersonalizeResult result = nfcOps.personalize(masterKey, url);

            if (result.success && itemCd != null) {
                NfcItemMapping mapping = new NfcItemMapping(result.uid, itemCd, url);
                mappingRepository.save(mapping);
                System.out.println("NFC mapping saved to DB - UID: " + result.uid + ", Item Code: " + itemCd);
            }

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        } finally {
            nfcLock.unlock();
        }
    }
}
