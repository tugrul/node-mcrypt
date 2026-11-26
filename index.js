'use strict';

var crypto = require('crypto');
var binding = require('bindings')('mcrypt');

// The addon has no random source of its own. The IV comes from the generator
// that Node uses for keys.
binding.MCrypt.prototype.generateIv = function generateIv() {
    return crypto.randomBytes(this.getIvSize());
};

module.exports = binding;
