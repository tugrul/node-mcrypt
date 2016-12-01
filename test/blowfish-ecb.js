
var mcrypt = require('..');
var assert = require('assert');

describe('MCrypt instance (BLOWFISH-ECB)', function() {
    var mc = new mcrypt.MCrypt('blowfish', 'ecb');

    it('should be an object', function() {
        assert(typeof mc == 'object', 'there is an object');
    });

    describe('open', function() {
        var key = 'YpQ3SXbNe9O/Vca/h+FVKQ==';
        var plaintext = '1165096\0';
        var ciphertext = 'LRo7D+VTxVw=';

        it('should open without error', function() {
            assert.doesNotThrow(function() {
                mc.validateKeySize(false);
                mc.open(new Buffer(key, 'base64'));
            }, 'there is error when opened with key');
        });

        describe('encrypt', function() {
            it('plaintext and decrypted ciphertext should be same', function(){
                assert.equal(ciphertext, mc.encrypt(plaintext).toString('base64'), 'ciphertext are not same');

            });
        });

        describe('decrypt', function() {
            it('ciphertext and encrypted plaintext should be same', function(){
                var result = mc.decrypt(new Buffer(ciphertext, 'base64')).toString();
                assert.equal(plaintext, result, 'plaintext are not same');
            });
        });
    });
});
