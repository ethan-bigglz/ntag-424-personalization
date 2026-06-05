const { aesCmac } = require('node-aes-cmac');
const key = Buffer.alloc(16).fill(0); // Dummy key
const input = Buffer.alloc(10).fill(0); // Dummy input
const out = aesCmac(key, input, { returnAsBuffer: true });
console.log('CMAC Buffer:', out.toString('hex'));

let oddBytes = Buffer.alloc(8);
for(let i=0; i<8; i++) {
  oddBytes[i] = out[i*2 + 1];
}
console.log('Odd Bytes:', oddBytes.toString('hex'));
