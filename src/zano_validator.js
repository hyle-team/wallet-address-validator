var cryptoUtils = require('./crypto/utils');
var cnBase58 = require('./crypto/cnBase58');

var DEFAULT_NETWORK_TYPE = 'prod';
var addressRegTest = new RegExp('^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{97,150}$');

function validateNetwork(decoded, currency, networkType, addressType)
{

    const substr = decoded.slice(0, 4).toString('hex');
    if(decoded.slice(0, 4).toString('hex') === "c501" ||
        decoded.slice(0, 4).toString('hex') === "f86c" ||
        decoded.slice(0, 4).toString('hex') === "f86d" ||
        decoded.slice(0, 6).toString('hex') === "c8b102" ||
        decoded.slice(0, 6).toString('hex') === "c99402"
    ) 
    {
        return true;
    }else{
        return false;
    }
    /* 
    possible tags: c501, f86c, f86d, c8b102, c99402
    */
}

function hextobin(hex) {
    if (hex.length % 2 !== 0) return null;
    var res = new Uint8Array(hex.length / 2);
    for (var i = 0; i < hex.length / 2; ++i) {
        res[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return res;
}

module.exports = {
    isValidAddress: function (address, currency, networkType) {
        networkType = networkType || DEFAULT_NETWORK_TYPE;
        var addressType = 'standard';
        if(!addressRegTest.test(address))
        {
            return false;
        }

        var decodedAddrStr = cnBase58.decode(address);
        if(!decodedAddrStr)
            return false;

        if(!validateNetwork(decodedAddrStr, currency, networkType, addressType))
            return false;

        var addrChecksum = decodedAddrStr.slice(-8);
        var hashChecksum = cryptoUtils.keccak256Checksum(hextobin(decodedAddrStr.slice(0, -8)));
        
        return addrChecksum === hashChecksum;
    }
};
