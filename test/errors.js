
var mcrypt = require('..');
var assert = require('assert');
var childProcess = require('child_process');
var path = require('path');

// Runs a script in a process of its own, with gc() available, and returns
// what it printed. A fault that shows only when memory is released would
// otherwise take the test runner down with it.
function run(body) {
    var script = 'var mcrypt = require(' + JSON.stringify(path.join(__dirname, '..')) + ');' + body;

    return childProcess.execFileSync(process.execPath, ['--expose-gc', '-e', script]).toString();
}

function repeat(text, count) {
    return new Array(count + 1).join(text);
}

// a stream algorithm opens only in stream mode, a block algorithm in any other
function open(algo) {
    var mc;

    try {
        mc = new mcrypt.MCrypt(algo, 'ecb');
    } catch (e) {
        mc = new mcrypt.MCrypt(algo, 'stream');
    }

    mc.open(repeat('k', mc.getKeySize()));

    return mc;
}

describe('errors', function() {

    it('should leave the process alive when encrypt and decrypt fail', function() {
        this.timeout(60000);

        var output = run(
            'var thrown = 0;' +
            'function attempt(mc) {' +
            '    try { mc.encrypt("0123456789abcdef"); } catch (e) { thrown++; }' +
            '    try { mc.decrypt("0123456789abcdef"); } catch (e) { thrown++; }' +
            '}' +
            'for (var i = 0; i < 200; i++) {' +
            '    attempt(new mcrypt.MCrypt("rijndael-128", "cbc"));' +          // open() was not called
            '    var mc = new mcrypt.MCrypt("rijndael-128", "ecb");' +
            '    mc.validateKeySize(false);' +
            '    mc.open(new Array(41).join("k"));' +                           // 40 bytes, the longest key is 32
            '    attempt(mc);' +
            '}' +
            'gc(); gc();' +
            'setTimeout(function() { gc(); process.stdout.write("thrown " + thrown); }, 50);'
        );

        assert.equal(output, 'thrown 800');
    });

    it('should throw for an unknown algorithm when called without new', function() {
        this.timeout(60000);

        var output = run(
            'try { mcrypt.MCrypt("deso", "ecb"); process.stdout.write("did not throw"); }' +
            'catch (e) { process.stdout.write("threw " + e.message); }'
        );

        assert.equal(output, 'threw MCrypt module could not open');
    });

    it('should report the first thing that is wrong', function() {
        var mc = new mcrypt.MCrypt('rijndael-128', 'cbc');
        var key = '0123456789abcdef';

        assert.throws(function() { new mcrypt.MCrypt(); }, /Missing parameters/);
        assert.throws(function() { mc.open(); }, /Key should be specified/);
        assert.throws(function() { mc.open(42); }, /Key has got incorrect type/);
        assert.throws(function() { mc.open('short', 'badiv'); }, /Invalid key size/);
        assert.throws(function() { mc.open(key, 42); }, /Iv has got incorrect type/);
        assert.throws(function() { mc.open(key, 'badiv'); }, /Invalid iv size/);
        assert.throws(function() { mc.encrypt(); }, /Plaintext should be specified/);
        assert.throws(function() { mc.encrypt(42); }, /Plaintext has got incorrect type/);
        assert.throws(function() { mc.decrypt(); }, /Ciphertext should be specified/);
        assert.throws(function() { mc.decrypt(42); }, /Ciphertext has got incorrect type/);
    });
});

describe('iv', function() {
    var key = '0123456789abcdef';
    var plaintext = 'some text some text some text some text';

    it('should be filled up with zero bytes when it is shorter than the iv size', function() {
        var padded = new mcrypt.MCrypt('rijndael-256', 'cbc');

        padded.validateKeySize(false);
        padded.open(key, 'foobar' + repeat('\0', 26));

        var expected = padded.encrypt(plaintext).toString('hex');

        for (var i = 0; i < 50; i++) {
            var mc = new mcrypt.MCrypt('rijndael-256', 'cbc');

            mc.validateKeySize(false);
            mc.validateIvSize(false);
            mc.open(key, 'foobar');

            var ciphertext = mc.encrypt(plaintext);

            assert.equal(ciphertext.toString('hex'), expected, 'ciphertext is not the one of the padded iv');
            assert.equal(mc.decrypt(ciphertext).toString().replace(/\0+$/, ''), plaintext, 'plaintext did not come back');
        }
    });

    it('should be zero bytes when a mode uses one and none is given', function() {
        ['cbc', 'cfb', 'ofb', 'ncfb', 'nofb', 'ctr'].forEach(function(mode) {
            var zero = new mcrypt.MCrypt('rijndael-128', mode);

            zero.open(key, repeat('\0', 16));

            var expected = zero.encrypt(plaintext).toString('hex');

            for (var i = 0; i < 20; i++) {
                var mc = new mcrypt.MCrypt('rijndael-128', mode);

                mc.open(key);

                assert.equal(mc.encrypt(plaintext).toString('hex'), expected, 'ciphertext is not the one of a zero iv in ' + mode);
            }
        });
    });
});

describe('empty input', function() {

    mcrypt.getAlgorithmNames().forEach(function(algo) {
        it('should give an empty Buffer for ' + algo, function() {
            var mc = open(algo);

            assert.equal(mc.encrypt('').length, 0, 'encrypt of an empty string');
            assert.equal(mc.encrypt(Buffer.concat([])).length, 0, 'encrypt of an empty Buffer');
            assert.equal(mc.decrypt(Buffer.concat([])).length, 0, 'decrypt of an empty Buffer');
        });
    });
});
