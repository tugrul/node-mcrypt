
var mcrypt = require('..');
var assert = require('assert');
var childProcess = require('child_process');
var path = require('path');

describe('generateIv', function() {

    it('should return a Buffer of the iv size', function() {
        [['rijndael-128', 'cbc'], ['rijndael-256', 'cbc'], ['blowfish', 'cfb'], ['des', 'ecb'], ['arcfour', 'stream']].forEach(function(pair) {
            var mc = new mcrypt.MCrypt(pair[0], pair[1]);
            var iv = mc.generateIv();

            assert(Buffer.isBuffer(iv), 'there is a Buffer for ' + pair.join('-'));
            assert.equal(iv.length, mc.getIvSize(), 'length is the iv size for ' + pair.join('-'));
        });
    });

    it('should return a different iv on every call', function() {
        var mc = new mcrypt.MCrypt('rijndael-128', 'cbc');
        var seen = {};

        for (var i = 0; i < 1000; i++) {
            var iv = mc.generateIv().toString('hex');

            assert(!seen[iv], 'iv ' + iv + ' came twice');
            seen[iv] = true;
        }
    });

    it('should use every byte value', function() {
        // The chance that 65536 random bytes miss any value is about 1 in
        // 10^109. The generator this replaces never returned 0xff.
        var mc = new mcrypt.MCrypt('rijndael-128', 'cbc');
        var seen = [];
        var missing = [];

        for (var i = 0; i < 4096; i++) {
            var iv = mc.generateIv();

            for (var j = 0; j < iv.length; j++) {
                seen[iv[j]] = true;
            }
        }

        for (var value = 0; value < 256; value++) {
            if (!seen[value]) {
                missing.push(value);
            }
        }

        assert.deepEqual(missing, [], 'some byte values never came');
    });

    it('should not return the same iv in two processes', function() {
        this.timeout(60000);

        var script = 'var mcrypt = require(' + JSON.stringify(path.join(__dirname, '..')) + ');' +
            'var mc = new mcrypt.MCrypt("rijndael-128", "cbc");' +
            'process.stdout.write(mc.generateIv().toString("hex"));';

        var first = childProcess.execFileSync(process.execPath, ['-e', script]).toString();
        var second = childProcess.execFileSync(process.execPath, ['-e', script]).toString();

        assert.equal(first.length, 32, 'the first process printed an iv');
        assert.equal(second.length, 32, 'the second process printed an iv');
        assert.notEqual(first, second, 'both processes got ' + first);
    });
});
