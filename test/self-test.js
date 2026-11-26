
var mcrypt = require('..');
var assert = require('assert');

describe('selfTest', function() {

    // a stream algorithm opens only in stream mode, a block algorithm in any other
    function open(algo) {
        try {
            return new mcrypt.MCrypt(algo, 'ecb');
        } catch (e) {
            return new mcrypt.MCrypt(algo, 'stream');
        }
    }

    mcrypt.getAlgorithmNames().forEach(function(algo) {
        it('should return true for ' + algo, function() {
            assert.strictEqual(open(algo).selfTest(), true, 'the self test of ' + algo + ' failed');
        });
    });
});
