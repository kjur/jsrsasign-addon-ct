var assert = require('assert');
var rs = require("jsrsasign");
var addon1 = require('../index.js');
addon1.register(rs);

describe("extension handler", function() {
    let deepEqual = assert.deepEqual;
    it("test", function() {
	let pExpect;
	hIn = "0481f200f0007700b73efb24df9c4dba75f239c5ba58f46c5dfc42cf7a9f35c49e1d098125edb49900000184bd8725ac0000040300483046022100a51dc11ca18731b990698119453985fcb0043f6c0001fae51dab9c753b03ee8c0221008250a1a79dc269c6e3b70e3f7641355585d379c3e35a11c6bc98a1a0a8a2d158007500e83ed0da3ef5063532e75728bc896bc903d3cbd1116beceb69e1777d6d06bd6e00000184bd87259d0000040300463044022036b6dd5ff6ba16b652f15a6b3305c3c171722ac00a764941f4220a058c5fb0e80220182fc64a6b55c0fa47d5ecca8b3055165677385441967daaec7eb88f2426b37e";
	pExpect = {
	    extname: "id-ce-embeddedSCT-CTv1",
	    critical: true,
	    array: [{
		version: 0,
		logid: 'tz77JN+cTbp18jnFulj0bF38Qs96nzXEnh0JgSXttJk=',
		timestamp: '20221128091741.676Z',
		sigalg: 'SHA256withECDSA P-256',
		sighex: '3046022100a51dc11ca18731b990698119453985fcb0043f6c0001fae51dab9c753b03ee8c0221008250a1a79dc269c6e3b70e3f7641355585d379c3e35a11c6bc98a1a0a8a2d158'
	    },{
		version: 0,
		logid: '6D7Q2j71BjUy51covIlryQPTy9ERa+zraeF3fW0GvW4=',
		timestamp: '20221128091741.661Z',
		sigalg: 'SHA256withECDSA P-256',
		sighex: '3044022036b6dd5ff6ba16b652f15a6b3305c3c171722ac00a764941f4220a058c5fb0e80220182fc64a6b55c0fa47d5ecca8b3055165677385441967daaec7eb88f2426b37e'
	    }]
	};
	deepEqual(addon1.extParserSCTV1("1.3.6.1.4.1.11129.2.4.2", true, hIn), pExpect);
    });
});
