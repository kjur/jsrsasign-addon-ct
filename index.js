const VERSION = "0.9.1";
const VERSION_FULL = "jsrsasign-addon-ct 0.9.1 (c) Kenji Urushima github.com/kjur/jsrsasign-addon-ct";

const OIDs = {
    // RFC 9162
    "id-ce-embeddedSCT-CTv1":	"1.3.6.1.4.1.11129.2.4.2"
};

let _jsrsasign = null;
let _KJUR = null;
let _X509 = null;
let _ASN1HEX = null;

function register(jsrsasign) {
    _jsrsasign = jsrsasign;
    _KJUR = _jsrsasign.KJUR;
    _X509 = _jsrsasign.X509;
    _ASN1HEX = _jsrsasign.ASN1HEX;
    _KJUR.asn1.x509.OID.registerOIDs(OIDs);
    _X509.registExtParser("1.3.6.1.4.1.11129.2.4.2", extParserSCTV1);
}

function _getSCT(hSCT) {
    try {
	let sTS = hSCT.slice(66, 66 + 16);
	let iTS = parseInt(sTS, 16);
	let hLogID = hSCT.slice(2, 2 + 64);
	let b64LogID = _jsrsasign.hextob64(hLogID);
	let sigalg = hSCT.slice(86, 86 + 4);
	if (sigalg == "0403") sigalg = "SHA256withECDSA P-256";
	if (sigalg == "0807") sigalg = "Ed25519";
	let result = {
	    version: parseInt(hSCT.slice(0, 2), 16), // version byte
	    logid: b64LogID, // logid uint64
	    timestamp: _jsrsasign.msectozulu(iTS), // timestamp number(8)
	    sigalg: sigalg, // sigalg
	    sighex: hSCT.slice(94) // sig
	};
	return result;
    } catch(ex) {
	throw new Error("SCT parse error:" + ex);
    }
}

function _getSCTHexArray(hSCTList) {
    let a = [];
    try {
	let h2 = hSCTList.slice(4);
	while (h2 != "") {
	    let len = parseInt(h2.slice(0, 4), 16) * 2;
	    let hSCT = h2.slice(4, 4 + len);
	    a.push(_getSCT(hSCT));
	    h2 = h2.slice(4 + len);
	}
	return a;
    } catch(ex) {
	throw new Error("embedded SCT list parse error: " + ex);
    }
}

function extParserSCTV1(oid, critical, hExtV) {
    try {
	// SignedCertificateTimestampList
	let h = _ASN1HEX.getV(hExtV, 0);
	var result = {
	    extname: _KJUR.asn1.x509.OID.oid2name(oid),
	    array: _getSCTHexArray(h)
	};
	if (critical) result.critical = true;
	return result;
    } catch(ex) {
	return undefined;
    }
}

exports.VERSION = VERSION;
exports.VERSION_FULL = VERSION_FULL;
exports.OIDs = OIDs;
exports.register = register;
exports.extParserSCTV1 = extParserSCTV1;
