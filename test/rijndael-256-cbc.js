
var mcrypt = require('..');
var assert = require('assert');

describe('MCrypt instance (RIJNDAEL-256-CBC)', function() {
    var mc = new mcrypt.MCrypt('rijndael-256', 'cbc');

    it('should be an object', function() {
        assert(typeof mc == 'object', 'there is an object');
    });

    describe('open', function() {
        var key = '32charteststring32charteststring';
        var plaintext = 'super secret stuff. super secret';
        var ciphertext = 'bpbeXZrsbiTtMsIRxNBNBA+9ZViHZObhak42fLgmPQg=';
        var iv = '1mTHy+gyVcNGjXmgXYLy6aK2JJoEPSLNJ2YhG/43gtU=';

        it('should open without error', function() {
            assert.doesNotThrow(function() {
                mc.validateKeySize(false);
                mc.open(key, new Buffer(iv, 'base64'));
            }, 'there is error when opened with key');
        });
        
        describe('encrypt', function() {
            it('plaintext and decrypted ciphertext should be same', function(){
                assert.equal(ciphertext, mc.encrypt(plaintext).toString('base64'), 'ciphertext are not same');

            });
        });

        describe('decrypt', function() {
            it('ciphertext and encrypted plaintext should be same', function(){
                assert.equal(plaintext, mc.decrypt(new Buffer(ciphertext, 'base64')).toString().trim(), 'plaintext are not same');
            });
        });
    });
});
