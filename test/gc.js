
var assert = require('assert');
var childProcess = require('child_process');
var path = require('path');

// Node 24.19.0 to 24.21.0 abort the process when an object whose class
// extends node::ObjectWrap is garbage collected: the destructor removes a
// cleanup hook, which needs a current context, and the collector runs it
// without one. The addon extends Nan::ObjectWrap for that reason.
//
// On every other version of Node these tests pass with either base class.
// They count in the CI job that runs on 24.21.0.

// Runs a script in a process of its own, with gc() available, and returns
// what it printed. An abort ends that process and fails one test.
function run(body) {
    var script = 'var mcrypt = require(' + JSON.stringify(path.join(__dirname, '..')) + ');' + body;

    return childProcess.execFileSync(process.execPath, ['--expose-gc', '-e', script]).toString();
}

describe('garbage collection', function() {

    it('should collect block cipher objects', function() {
        this.timeout(120000);

        var output = run(
            'for (var i = 0; i < 5000; i++) {' +
            '    var mc = new mcrypt.MCrypt("rijndael-128", "cbc");' +
            '    mc.open("0123456789abcdef", mc.generateIv());' +
            '    mc.decrypt(mc.encrypt("0123456789abcdef"));' +
            '}' +
            'gc(); gc();' +
            'process.stdout.write("survived");'
        );

        assert.equal(output, 'survived');
    });

    it('should collect stream cipher objects', function() {
        this.timeout(120000);

        var output = run(
            'for (var i = 0; i < 5000; i++) {' +
            '    var mc = new mcrypt.MCrypt("arcfour", "stream");' +
            '    mc.validateKeySize(false);' +
            '    mc.open("0123456789abcdef");' +
            '    mc.encrypt("some text");' +
            '}' +
            'gc(); gc();' +
            'process.stdout.write("survived");'
        );

        assert.equal(output, 'survived');
    });

    it('should collect objects that were never opened or failed to construct', function() {
        this.timeout(120000);

        var output = run(
            'var failed = 0;' +
            'for (var i = 0; i < 3000; i++) {' +
            '    new mcrypt.MCrypt("des", "ecb");' +
            '    var mc = new mcrypt.MCrypt("blowfish", "cfb");' +
            '    mc.validateKeySize(false);' +
            '    mc.open("some key", mc.generateIv());' +
            '    try { new mcrypt.MCrypt("no such algorithm", "ecb"); } catch (e) { failed++; }' +
            '}' +
            'gc(); gc(); gc();' +
            'process.stdout.write("survived, " + failed + " failed");'
        );

        assert.equal(output, 'survived, 3000 failed');
    });

    it('should collect when the garbage collector runs on its own', function() {
        this.timeout(120000);

        // no gc() here: enough garbage is made for the collector to start by
        // itself, between turns of the event loop as well as inside one
        var output = run(
            'var rounds = 0;' +
            'function round() {' +
            '    for (var i = 0; i < 2000; i++) {' +
            '        var mc = new mcrypt.MCrypt("rijndael-256", "cbc");' +
            '        mc.validateKeySize(false);' +
            '        mc.open("0123456789abcdef", mc.generateIv());' +
            '        mc.encrypt(new Array(1025).join("x"));' +
            '    }' +
            '    if (++rounds < 25) { setImmediate(round); } else { process.stdout.write("survived " + rounds + " rounds"); }' +
            '}' +
            'round();'
        );

        assert.equal(output, 'survived 25 rounds');
    });

    it('should reach the end of the process with objects alive', function() {
        this.timeout(120000);

        var output = run(
            'var live = [];' +
            'for (var i = 0; i < 1000; i++) {' +
            '    var mc = new mcrypt.MCrypt("rijndael-128", "cbc");' +
            '    mc.open("0123456789abcdef", mc.generateIv());' +
            '    live.push(mc);' +
            '}' +
            'process.stdout.write("reached the end with " + live.length + " alive");'
        );

        assert.equal(output, 'reached the end with 1000 alive');
    });
});
