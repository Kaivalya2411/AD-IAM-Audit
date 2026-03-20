// Simple MD5 implementation
  function md5(str) {
    function safeAdd(x,y){let lsw=(x&0xFFFF)+(y&0xFFFF);return((x>>16)+(y>>16)+(lsw>>16))<<16|lsw&0xFFFF}
    function bitRotateLeft(num,cnt){return num<<cnt|num>>>32-cnt}
    function md5cmn(q,a,b,x,s,t){return safeAdd(bitRotateLeft(safeAdd(safeAdd(a,q),safeAdd(x,t)),s),b)}
    function md5ff(a,b,c,d,x,s,t){return md5cmn(b&c|~b&d,a,b,x,s,t)}
    function md5gg(a,b,c,d,x,s,t){return md5cmn(b&d|c&~d,a,b,x,s,t)}
    function md5hh(a,b,c,d,x,s,t){return md5cmn(b^c^d,a,b,x,s,t)}
    function md5ii(a,b,c,d,x,s,t){return md5cmn(c^(b|~d),a,b,x,s,t)}
    str=unescape(encodeURIComponent(str));
    let b=[];for(let i=0;i<str.length;i++)b[i>>2]|=str.charCodeAt(i)<<(i%4)*8;
    b[str.length>>2]|=0x80<<(str.length%4)*8;b[(((str.length+8)>>6)+1)*16-2]=str.length*8;
    let a=1732584193,bv=-271733879,c=-1732584194,d=271733878;
    for(let i=0;i<b.length;i+=16){let oa=a,ob=bv,oc=c,od=d;
      a=md5ff(a,bv,c,d,b[i],7,-680876936);d=md5ff(d,a,bv,c,b[i+1],12,-389564586);
      c=md5ff(c,d,a,bv,b[i+2],17,606105819);bv=md5ff(bv,c,d,a,b[i+3],22,-1044525330);
      a=md5ff(a,bv,c,d,b[i+4],7,-176418897);d=md5ff(d,a,bv,c,b[i+5],12,1200080426);
      c=md5ff(c,d,a,bv,b[i+6],17,-1473231341);bv=md5ff(bv,c,d,a,b[i+7],22,-45705983);
      a=md5ff(a,bv,c,d,b[i+8],7,1770035416);d=md5ff(d,a,bv,c,b[i+9],12,-1958414417);
      c=md5ff(c,d,a,bv,b[i+10],17,-42063);bv=md5ff(bv,c,d,a,b[i+11],22,-1990404162);
      a=md5ff(a,bv,c,d,b[i+12],7,1804603682);d=md5ff(d,a,bv,c,b[i+13],12,-40341101);
      c=md5ff(c,d,a,bv,b[i+14],17,-1502002290);bv=md5ff(bv,c,d,a,b[i+15],22,1236535329);
      a=md5gg(a,bv,c,d,b[i+1],5,-165796510);d=md5gg(d,a,bv,c,b[i+6],9,-1069501632);
      c=md5gg(c,d,a,bv,b[i+11],14,643717713);bv=md5gg(bv,c,d,a,b[i],20,-373897302);
      a=md5gg(a,bv,c,d,b[i+5],5,-701558691);d=md5gg(d,a,bv,c,b[i+10],9,38016083);
      c=md5gg(c,d,a,bv,b[i+15],14,-660478335);bv=md5gg(bv,c,d,a,b[i+4],20,-405537848);
      a=md5gg(a,bv,c,d,b[i+9],5,568446438);d=md5gg(d,a,bv,c,b[i+14],9,-1019803690);
      c=md5gg(c,d,a,bv,b[i+3],14,-187363961);bv=md5gg(bv,c,d,a,b[i+8],20,1163531501);
      a=md5gg(a,bv,c,d,b[i+13],5,-1444681467);d=md5gg(d,a,bv,c,b[i+2],9,-51403784);
      c=md5gg(c,d,a,bv,b[i+7],14,1735328473);bv=md5gg(bv,c,d,a,b[i+12],20,-1926607734);
      a=md5hh(a,bv,c,d,b[i+5],4,-378558);d=md5hh(d,a,bv,c,b[i+8],11,-2022574463);
      c=md5hh(c,d,a,bv,b[i+11],16,1839030562);bv=md5hh(bv,c,d,a,b[i+14],23,-35309556);
      a=md5hh(a,bv,c,d,b[i+1],4,-1530992060);d=md5hh(d,a,bv,c,b[i+4],11,1272893353);
      c=md5hh(c,d,a,bv,b[i+7],16,-155497632);bv=md5hh(bv,c,d,a,b[i+10],23,-1094730640);
      a=md5hh(a,bv,c,d,b[i+13],4,681279174);d=md5hh(d,a,bv,c,b[i],11,-358537222);
      c=md5hh(c,d,a,bv,b[i+3],16,-722521979);bv=md5hh(bv,c,d,a,b[i+6],23,76029189);
      a=md5hh(a,bv,c,d,b[i+9],4,-640364487);d=md5hh(d,a,bv,c,b[i+12],11,-421815835);
      c=md5hh(c,d,a,bv,b[i+15],16,530742520);bv=md5hh(bv,c,d,a,b[i+2],23,-995338651);
      a=md5ii(a,bv,c,d,b[i],6,-198630844);d=md5ii(d,a,bv,c,b[i+7],10,1126891415);
      c=md5ii(c,d,a,bv,b[i+14],15,-1416354905);bv=md5ii(bv,c,d,a,b[i+5],21,-57434055);
      a=md5ii(a,bv,c,d,b[i+12],6,1700485571);d=md5ii(d,a,bv,c,b[i+3],10,-1894986606);
      c=md5ii(c,d,a,bv,b[i+10],15,-1051523);bv=md5ii(bv,c,d,a,b[i+1],21,-2054922799);
      a=md5ii(a,bv,c,d,b[i+8],6,1873313359);d=md5ii(d,a,bv,c,b[i+15],10,-30611744);
      c=md5ii(c,d,a,bv,b[i+6],15,-1560198380);bv=md5ii(bv,c,d,a,b[i+13],21,1309151649);
      a=md5ii(a,bv,c,d,b[i+4],6,-145523070);d=md5ii(d,a,bv,c,b[i+11],10,-1120210379);
      c=md5ii(c,d,a,bv,b[i+2],15,718787259);bv=md5ii(bv,c,d,a,b[i+9],21,-343485551);
      a=safeAdd(a,oa);bv=safeAdd(bv,ob);c=safeAdd(c,oc);d=safeAdd(d,od)}
    return [a,bv,c,d].map(n=>(n<0?n+0x100000000:n).toString(16).padStart(8,'0').match(/../g).map(h=>(parseInt(h,16)&0xFF).toString(16).padStart(2,'0')+''+((parseInt(h,16)>>4)&0xF).toString(16)+(parseInt(h,16)&0xF).toString(16)).join('')).join('');
  }
