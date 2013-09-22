
var MCrypt = require('../build/Release/mcrypt').MCrypt;

var blowfishCfb = new MCrypt('blowfish', 'cfb');

console.log(blowfishCfb.selfTest());

/*var iv = blowfishCfb.generateIv();

blowfishCfb.open('somekey', iv);

var ciphertext = blowfishCfb.encrypt('sometext');

console.log(Buffer.concat([iv, ciphertext]).toString('base64'));
*/