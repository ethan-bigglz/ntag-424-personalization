const { NFC } = require('nfc-pcsc');
const nfc = new NFC();

console.log('Searching for NFC readers...');

nfc.on('reader', reader => {
  console.log('Found NFC reader:', reader.reader.name);
  nfc.close(); // or just process.exit(0)
  process.exit(0);
});

nfc.on('error', err => {
  console.log('Error:', err);
  process.exit(1);
});

setTimeout(() => {
  console.log('Timeout searching for readers. Assuming none found.');
  process.exit(1);
}, 5000);
