import{connect}from'cloudflare:sockets';
const CONFIG={
  uuid:' ',
  password:' ',
  userBufferer:true,
  enableHybridDrive:true,
  initialBufferSize:128*1024,
  maxBufferSize:512*1024,
  flushTimeoutMs:10,
  concurrency:1,
  concurrentOnlyDomain:false,
  dohEndpoints:['https://cloudflare-dns.com/dns-query','https://dns.google/dns-query'],
  dns64Prefix: '64:ff9b::/96',
  dohFetchOptions:{method:'POST',headers:{'content-type':'application/dns-message'}},
  proxyIpAddrs:{EU:'',AS:'',JP:'',US:''},
  finallyProxyHost:'',
  coloRegions:{
    JP:new Set(['FUK','ICN','KIX','NRT','OKA']),
    EU:new Set(['ACC','ADB','ALA','ALG','AMM','AMS','ARN','ATH','BAH','BCN','BEG','BGW','BOD','BRU','BTS','BUD','CAI','CDG','CPH','CPT','DAR','DKR','DMM','DOH','DUB','DUR','DUS','DXB','EBB','EDI','EVN','FCO','FRA','GOT','GVA','HAM','HEL','HRE','IST','JED','JIB','JNB','KBP','KEF','KWI','LAD','LED','LHR','LIS','LOS','LUX','LYS','MAD','MAN','MCT','MPM','MRS','MUC','MXP','NBO','OSL','OTP','PMO','PRG','RIX','RUH','RUN','SKG','SOF','STR','TBS','TLL','TLV','TUN','VIE','VNO','WAW','ZAG','ZRH']),
    AS:new Set(['ADL','AKL','AMD','BKK','BLR','BNE','BOM','CBR','CCU','CEB','CGK','CMB','COK','DAC','DEL','HAN','HKG','HYD','ISB','JHB','JOG','KCH','KHH','KHI','KTM','KUL','LHE','MAA','MEL','MFM','MLE','MNL','NAG','NOU','PAT','PBH','PER','PNH','SGN','SIN','SYD','TPE','ULN','VTE'])
  },
  maintainHtml:`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Website Under Maintenance</title><style>body { text-align: center; padding: 100px 20px; font-family: system-ui, -apple-system, sans-serif; background-color: #f8f8f8; color: #333; } .container { max-width: 600px; margin: 0 auto; background: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); } h1 { font-size: 32px; margin-bottom: 10px; color: #e74c3c; } p { font-size: 18px; color: #666; line-height: 1.6; }</style></head><body><div class="container"><h1>Website Under Maintenance</h1><p>We are currently performing necessary system upgrades. Services will resume shortly. Thank you for your patience.</p></div></body></html>`
};
const[textEncoder,textDecoder,socks5Init,httpHeaderEnd]=[new TextEncoder(),new TextDecoder(),new Uint8Array([5,2,0,2]),new Uint8Array([13,10,13,10])];
const coloToProxyMap=new Map(Object.entries(CONFIG.coloRegions).flatMap(([region,colos])=>Array.from(colos,colo=>[colo,CONFIG.proxyIpAddrs[region]])));
const uuidToBytes=new Uint8Array(CONFIG.uuid.replace(/-/g,'').match(/.{2}/g).map(byte=>parseInt(byte,16)));
const[uuidPart1,uuidPart2]=[new DataView(uuidToBytes.buffer).getBigUint64(0),new DataView(uuidToBytes.buffer).getBigUint64(8)];
const expectedHash=sha224Hash(CONFIG.password);
const expectedHashBytes=textEncoder.encode(expectedHash);
function sha224Hash(message){
  const kConstants=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const toUtf8=(str)=>unescape(encodeURIComponent(str));
  const bytesToHex=(byteArray)=>{let hexString='';for(let i=0;i<byteArray.length;i++){hexString+=((byteArray[i]>>>4)&0x0F).toString(16)+(byteArray[i]&0x0F).toString(16);}return hexString;};
  const computeHash=(inputStr)=>{
    let hState=[0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4];
    const messageBitLength=inputStr.length*8;
    inputStr+=String.fromCharCode(0x80);
    while((inputStr.length*8)%512!==448)inputStr+=String.fromCharCode(0);
    const highBits=Math.floor(messageBitLength/0x100000000);
    const lowBits=messageBitLength&0xFFFFFFFF;
    inputStr+=String.fromCharCode((highBits>>>24)&0xFF,(highBits>>>16)&0xFF,(highBits>>>8)&0xFF,highBits&0xFF,(lowBits>>>24)&0xFF,(lowBits>>>16)&0xFF,(lowBits>>>8)&0xFF,lowBits&0xFF);
    const words=[];
    for(let i=0;i<inputStr.length;i+=4)words.push((inputStr.charCodeAt(i)<<24)|(inputStr.charCodeAt(i+1)<<16)|(inputStr.charCodeAt(i+2)<<8)|inputStr.charCodeAt(i+3));
    for(let i=0;i<words.length;i+=16){
      const w=new Array(64);
      for(let j=0;j<16;j++)w[j]=words[i+j];
      for(let j=16;j<64;j++){
        const s0=rotateRight(w[j-15],7)^rotateRight(w[j-15],18)^(w[j-15]>>>3);
        const s1=rotateRight(w[j-2],17)^rotateRight(w[j-2],19)^(w[j-2]>>>10);
        w[j]=(w[j-16]+s0+w[j-7]+s1)>>>0;
      }
      let[a,b,c,d,e,f,g,h]=hState;
      for(let j=0;j<64;j++){
        const S1=rotateRight(e,6)^rotateRight(e,11)^rotateRight(e,25);
        const ch=(e&f)^(~e&g);
        const temp1=(h+S1+ch+kConstants[j]+w[j])>>>0;
        const S0=rotateRight(a,2)^rotateRight(a,13)^rotateRight(a,22);
        const maj=(a&b)^(a&c)^(b&c);
        const temp2=(S0+maj)>>>0;
        h=g;g=f;f=e;e=(d+temp1)>>>0;d=c;c=b;b=a;a=(temp1+temp2)>>>0;
      }
      hState[0]=(hState[0]+a)>>>0;hState[1]=(hState[1]+b)>>>0;hState[2]=(hState[2]+c)>>>0;hState[3]=(hState[3]+d)>>>0;
      hState[4]=(hState[4]+e)>>>0;hState[5]=(hState[5]+f)>>>0;hState[6]=(hState[6]+g)>>>0;hState[7]=(hState[7]+h)>>>0;
    }
    return hState.slice(0,7);
  };
  const rotateRight=(value,shift)=>((value>>>shift)|(value<<(32-shift)))>>>0;
  const utf8Message=toUtf8(message);
  const hashWords=computeHash(utf8Message);
  return bytesToHex(hashWords.flatMap(h=>[(h>>>24)&0xFF,(h>>>16)&0xFF,(h>>>8)&0xFF,h&0xFF]));
}
const binaryAddrToString=(addrType,addrBytes)=>{
  if(addrType===3)return textDecoder.decode(addrBytes);
  if(addrType===1)return`${addrBytes[0]}.${addrBytes[1]}.${addrBytes[2]}.${addrBytes[3]}`;
  if(addrType===4){
    const view=new DataView(addrBytes.buffer,addrBytes.byteOffset,addrBytes.byteLength);
    let ipv6=view.getUint16(0).toString(16);
    for(let i=1;i<8;i++)ipv6+=':'+view.getUint16(i*2).toString(16);
    return`[${ipv6}]`;
  }
};
const parseHostPort=(addr,defaultPort)=>{
  if(addr.startsWith('[')){
    const sepIndex=addr.indexOf(']:');
    if(sepIndex!==-1){
      const host=addr.substring(0,sepIndex+1);
      const portStr=addr.substring(sepIndex+2);
      const port=parseInt(portStr,10);
      if(!isNaN(port))return[host,port];
    }
    return[addr,defaultPort];
  }
  const tpIndex=addr.indexOf('.tp');
  const lastColon=addr.lastIndexOf(':');
  if(tpIndex!==-1&&lastColon===-1){
    const portStartIndex=tpIndex+3;
    let portEndIndex=portStartIndex;
    while(portEndIndex<addr.length&&addr.charCodeAt(portEndIndex)>=48—&&addr.charCodeAt(portEndIndex)<=57)portEndIndex++;
    if(portEndIndex>portStartIndex)return[addr,parseInt(addr.substring(portStartIndex,portEndIndex),10)];
  }
  if(lastColon===-1)return[addr,defaultPort];
  const host=addr.substring(0,lastColon);
  const port=parseInt(addr.substring(lastColon+1),10);
  return!isNaN(port)?[host,port]:[host,defaultPort];
};
const parseAuthString=(authParam)=>{
  let username,password,hostStr;
  const atIndex=authParam.lastIndexOf('@');
  if(atIndex===-1){hostStr=authParam;}else{
    const cred=authParam.substring(0,atIndex);
    hostStr=authParam.substring(atIndex+1);
    const colonIndex=cred.indexOf(':');
    if(colonIndex===-1){username=cred;}else{
      username=cred.substring(0,colonIndex);
      password=cred.substring(colonIndex+1);
    }
  }
  const[hostname,port]=parseHostPort(hostStr,1080);
  return{username,password,hostname,port};
};
const isIPv4optimized=(str)=>{
  if(str.length>15||str.length<7)return false;
  let part=0,dots=0,partLen=0;
  for(let i=0;i<str.length;i++){
    const charCode=str.charCodeAt(i);
    if(charCode===46){
      dots++;
      if(dots>3||partLen===0||(str.charCodeAt(i-1)===48&&partLen>1))return false;
      part=0;partLen=0;
    }else if(charCode>=48&&charCode<=57){
      partLen++;
      part=part*10+(charCode-48);
      if(part>255||partLen>3)return false;
    }else{return false;}
  }
  return!(dots!==3||partLen===0||(str.charCodeAt(str.length-partLen)===48&&partLen>1));
};
const isDomainName=(inputStr)=>{
  if(!CONFIG.concurrentOnlyDomain)return true;
  if(!inputStr||inputStr[0]==='[')return false;
  if(inputStr[0].charCodeAt(0)<48||inputStr[0].charCodeAt(0)>57)return true;
  return!isIPv4optimized(inputStr);
};
async function resolveToIPv6(target) {
    if (!CONFIG.dns64Prefix) return target;
    const isIPv6 = (str) => str.includes(':');
    const isIPv4 = (str) => /^(?:(??:25[0-8]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$/.test(str);
    if (isIPv6(target)) return target;
    let ipv4 = target;
    if (!isIPv4(target)) {
        try {
            const response = await fetch(`${CONFIG.dohEndpoints[0]}?name=${target}&type=A`, {
                headers: { 'Accept': 'application/dns-json' }
            });
            if (!response.ok) throw new Error('DNS query failed');
            const data = await response.json();
            const record = (data.Answer || ]).find(r => r.type === 1);
            if (!record) throw new Error('No A record found');
            ipv4 = record.data;
        } catch (e) {
            return target;
        }
    }
    
    let prefix = CONFIG.dns64Prefix.split('/')[0];
    if (prefix.endsWith(':')) {
        prefix = prefix.substring(0, prefix.length - 1);
    }
    const ipv4Bytes = ipv4.split('.').map(part => parseInt(part, 10));
    const hex = ipv4Bytes.map(part => part.toString(16).padStart(2, '0')).join('');
    return `[${prefix}:${hex.slice(0, 4)}:${hex.slice(4)}]`;
}
const concurrentConnect = async (hostname, port, addrType) => {
  const doConnect = async (targetHost, targetPort) => {
    const shouldConcurrent = !(CONFIG.concurrentOnlyDomain && addrType !== 3);
    const count = shouldConcurrent ? CONFIG.concurrency : 1;
    
    const socketPromises = Array(count).fil(null).map(async () => {
        const socket = connect({ hostname: targetHost, port: targetPort });
        await socket.opened;
        return socket;
    });
    return await Promise.any(socketPromises);
  };
  try {
    return await doConnect(hostname, port);
  } catch (error1) {
    try {
      if (CONFIG.finallyProxyHost) {
        return await doConnect(CONFIG.finallyProxyHost, port);
      }
    } catch (error2) {
    }
    if (CONFIG.dns64Prefix) {
      try {
        const ipv6Target = await resolveToIPv6(hostname);
        if (ipv6Target.replace(/[\[\]/g, '') !== hostname.replace(/[\[\]]/g, '')) {
           return await doConnect(ipv6Target, port);
        }
      } catch (error3) {
      }
    }
    throw error1;
  }
};
const connectViaSocksProxy=async(targetAddrType,targetPortNum,socksAuth,targetAddrBytes)=>{
  const addrType=isDomainName(socksAuth.hostname)?3:0;
  const socksSocket=await concurrentConnect(socksAuth.hostname,socksAuth.port,addrType);
  const writer=socksSocket.writable.getWriter();
  const reader=socksSocket.readable.getReader();
  try{
    await writer.write(socks5Init);
    const{value:authResponse}=await reader.read();
    if(!authResponse||authResponse[0]!==5||authResponse[1]===0xFF)return null;
    if(authResponse[1]===2){
      if(!socksAuth.username)return null;
      const userBytes=textEncoder.encode(socksAuth.username);
      const passBytes=textEncoder.encode(socksAuth.password||'');
      await writer.write(new Uint8Array([1,userBytes.length,...userBytes,passBytes.length,...passBytes]));
      const{value:authResult}=await reader.read();
      if(!authResult||authResult[0]!==1||authResult[1]!==0)return null;
    }else if(authResponse[1]!==0){return null;}
    await writer.write(new Uint8Array([5,1,0,targetAddrType,...(targetAddrType===3?[targetAddrBytes.length]:[]),...targetAddrBytes,targetPortNum>>8,targetPortNum&0xff]));
    const{value:finalResponse}=await reader.read(1);
    if(!finalResponse||finalResponse[1]!==0)return null;
    return socksSocket;
  }finally{
    writer?.releaseLock();
    reader?.releaseLock();
  }
};
const connectViaHtttpProxy=async(targetAddrType,targetPortNum,httpAuth,targetAddrBytes)=>{
  const{username,password,hostname,port}=httpAuth;
  const addrType=isDomainName(hostname)?3:0;
  const proxySocket=await concurrentConnect(hostname,port,addrType);
  const writer=proxySocket.writable.getWriter();
  const httpHost=binaryAddrToString(targetAddrType,targetAddrBytes);
  const requestHeaders=[`CONNECT ${httpHost}:${targetPortNum} HTTP/1.1`,`Host: ${httpHost}:${targetPortNum}`];
  if(username)requestHeaders.push(`Proxy-Authorization: Basic ${btoa(`${username}:${password||''}`)}`);
  requestHeaders.push('Proxy-Connection: Keep-Alive','Connection: Keep-Alive','\r\n');
  await writer.write(textEncoder.encode(requestHeaders.join('\r\n')));
  writer.releaseLock();
  const reader=proxySocket.readable.getReader();
  const chunks=[];
  let headerFound=false;
  try{
    while(!headerFound){
      const{value,done}=await reader.read();
      if(done)break;
      chunks.push(value);
      if(findSequence(chunks)!==-1)headerFound=true;
    }
    if(!headerFound){await proxySocket.close();return null;}
    let totalLen=chunks.reduce((acc,chunk)=>acc+chunk.length,0);
    const combined=new Uint8Array(totalLen);
    let offset=0;
    for(const chunk of chunks){combined.set(chunk,offset);offset+=chunk.length;}
    const responseStr=textDecoder.decode(combined.subarray(0,20));
    if(!responseStr.startsWith('HTTP/1.1 200')&&!responseStr.startsWith('HTTP/1.0 200')){
      await proxySocket.close();return null;
    }
    reader.releaseLock();
    return proxySocket;
  }catch{
    reader.releaseLock();
    await proxySocket.close();
    return null;
  }
};
const parseAddressAndPort=(buffer,offset,addrType)=>{
  let addressLength;
  if(addrType===3){addressLength=buffer[offset++];}
  else if(addrType===1){addressLength=4;}
  else if(addrType===4){addressLength=16;}
  else{return null;}
  const newOffset=offset+addressLength;
  if(newOffset>buffer.length)return null;
  const targetAddrBytes=buffer.subarray(offset,newOffset);
  return{targetAddrBytes,dataOffset:newOffset};
};
const parseRequestData=(firstChunk)=>{
  const dataView=new DataView(firstChunk.buffer);
  if(dataView.getBigUint64(1)!==uuidPart1||dataView.getBigUint64(9)!==uuidPart2)return null;
  let offset=17+firstChunk[17]+1;
  const command=firstChunk[offset+++];
  const port=dataView.getUint16(offset);
  if(command!==1&&port!==53)return null;
  offset+=2;
  let addrType=firstChunk[offset++];
  if(addrType===2||addrType===3)addrType+=1;
  const addressInfo=parseAddressAndPort(firstChunk,offset,addrType);
  if(!addressInfo)return null;
  return{addrType,...addressInfo,port,isDns:port===53};
};
const parseTransparent=(firstChunk)=>{
  const dataView=new DataView(firstChunk.buffer);
  for(let i=0;i<56;i++){if(firstChunk[i]!==expectedHashBytes[i])return null;}
  let offset=58;
  if(firstChunk[offset++]!==1)return null;
  const addrType=firstChunk[offset++];
  const addressInfo=parseAddressAndPort(firstChunk,offset,addrType);
  if(!addressInfo)return null;
  const port=dataView.getUint16(addressInfo.dataOffset);
  return{addrType,...addressInfo,port,dataOffset:addressInfo.dataOffset+4,isDns:port===53};
};
const parseShadow=(firstChunk)=>{
  const dataView=new DataView(firstChunk.buffer);
  const addrType=dataView.getUint8(0);
  let offset=1;
  const addressInfo=parseAddressAndPort(firstChunk,offset,addrType);
  if(!addressInfo)return null;
  const port=dataView.getUint16(addressInfo.dataOffset);
  return{addrType,...addressInfo,port,dataOffset:addressInfo.dataOffset+2,isDns:port===53};
};
const parseSocks5=(firstChunk)=>{
  if(firstChunk[0]!==5||firstChunk[10]!==1||firstChunk[2]!==0)return null;
  const addrType=firstChunk[3];
  const addressInfo=parseAddressAndPort(firstChunk,4,addrType);
  if(!addressInfo)return null;
  const port=new DataView(firstChunk.buffer).getUint16(addressInfo.dataOffset);
  return{addrType,...addressInfo,port,dataOffset:addressInfo.dataOffset+2,isDns:port===53,isSocks5:true};
};
const strategyExecutorMap=new Map([
  [0,async({addrType,port,targetAddrBytes})=>{
    const hostname=binaryAddrToString(addrType,targetAddrBytes);
    return concurrentConnect(hostname,port,addrType);
  }],
  [1,async({addrType,port,targetAddrBytes},param)=>{
    const socksAuth=parseAuthString(param);
    return connectViaSocksProxy(addrType,port,socksAuth,targetAddrBytes);
  }],
  [2,async({addrType,port,targetAddrBytes},param)=>{
    const httpAuth=parseAuthString(param);
    return connectViaHttpProxy(addrType,port,httpAuth,targetAddrBytes);
  }],
  [3,async(_parsedRequest,_param,{proxyHost,proxyPort})=>{
    const addrType=isDomainName(proxyHost)3:0;
    return concurrentConnect(proxyHost,proxyPort,addrType);
  }],
  [4,async(_parsedRequest,_param,_proxyHost)=>{
    return concurrentConnect(CONFIG.finallyProxyHost,443,3);
  }]
]);
const prepareProxyConfig=(request)=>{
  const url=request.url.substring(request.url.indexOf('/',10)+1);
  const cleanUrl=url.endsWith('/')?url.slice(0,-1):url;
  const lowerCleanUrl=cleanUrl.toLowerCase();
  const extract=(regex)=>cleanUrl.match(regex)?.[1];
  const gs5Param=(lowerCleanUrl.includes('gs5')||lowerCleanUrl.includes('s5all'))?extract(/(?:gs5|s5all)(?:=|:\/\/|%3A%2F%2F)([^&]+)/i):null;
  const ghttpParam=(lowerCleanUrl.includes('ghttp')||lowerCleanUrl.includes('httpall'))?extract(/(?:ghttp|httpall)(?:=|:\/\/|%3A%2F%2F)([^&]+)/i):null;
  const socksParam=gs5Param??((lowerCleanUrl.includes('s5')||lowerCleanUrl.includes('socks'))?extract(/(?:s5|socks)(?:=|:\/\/|%3A%2F%2F)([^&]+)/i):null);
  const httpParam=ghttpParam??(lowerCleanUrl.includes('http')?extract(/http(?:=|:\/\/|%3A%2F%2F)([^&]+)/i):null);
  const proxyAll=!!(gs5Param||ghttpParam)||lowerCleanUrl.includes('proxyall')||lowerCleanUrl.includes('globalproxy');
  const socksStrategies=socksParam?decodeURIComponent(socksParam).split(',').filter(Boolean).map(p=>({type:1,param:p.trim()})):[];
  const httpStrategies=httpParam?decodeURIComponent(httpParam).split(',').filter(Boolean).map(p=>({type:2,param:p.trim()})):[];
  let strategies=[],proxyHost,proxyPort;
  if(proxyAll){
    strategies.push(...socksStrategies,...httpStrategies);
    if(strategies.length===0)strategies.push({type:0});
  }else{
    strategies=[{type:0},...socksStrategies,...httpStrategies,{type:3},{type:4}];
    const ipParam=lowerCleanUrl.includes('ip=')?extract(/ip=([^&]+)/i):null;
    const proxyString=ipParam??coloToProxyMap.get(request.cf?.colo)??CONFIG.proxyIpAddrs.US;
    [proxyHost,proxyPort]=parseHostPort(decodeURIComponent(proxyString),443);
  }
  return{strategies,proxyHost,proxyPort};
};
const establishTcpConnection=async(parsedRequest,request)=>{
  const{strategies,proxyHost,proxyPort}=prepareProxyConfig(request);
  for(const strategy of strategies){
    const executor=strategyExecutorMap.get(strategy.type);
    if(!executor)continue;
    try{
      const tcpSocket=await executor(parsedRequest,strategy.param,{proxyHost,proxyPort});
      if(tcpSocket)return tcpSocket;
    }catch{}
  }
  return null;
};
const dohDnsHandler=async(webSocket,haveEarlyData,payload)=>{
  if(payload.byteLength<2)throw new Error();
  const dnsQueryData=payload.subarray(2);
  const resp=await Promise.any(CONFIG.dohEndpoints.map(endpoint=>
    fetch(endpoint,{...CONFIG.dohFetchOptions,body:dnsQueryData}).then(response=>{
      if(!response.ok)throw new Error();
      return response;
    })
  ));
  const dnsQueryResult=await resp.arrayBuffer();
  if(webSocket.readyState!==WebSocket.OPEN)throw new Error();
  const udpSize=dnsQueryResult.byteLength;
  const udpSizeBuffer=new Uint8Array([(udpSize>>8)&0xff,udpSize&0xff]);
  const packet=new Uint8Array(udpSizeBuffer.length+udpSize);
  packet.set(udpSizeBuffer,0);
  packet.set(new Uint8Array(dnsQueryResult),udpSizeBuffer.length);
  webSocket.send(packet);
  if(!haveEarlyData)webSocket.close();
};
const createBufferer=(initialChunk)=>{
  let buffer=new Uint8Array(CONFIG.initialBufferSize),offset=0,timerId=null,resolveResumeSignal=null;
  const flushBuffer=(controller)=>{
    if(offset>0){
      controller.enqueue(buffer.subarray(0,offset));
      buffer=new Uint8Array(CONFIG.initialBufferSize);
      offset=0;
    }
  };
  return new TransformStream({
    start(controller){
      if(initialChunk?.byteLength>0)controller.enqueue(initialChunk);
      if(!CONFIG.enableHybridDrive){
        timerId=setInterval((0)=>{
          flushBuffer(controller);
          if(resolveResumeSignal){resolveResumeSignal();resolveResumeSignal=null;}
        },CONFIG.flushTimeoutMs);
      }
    },
    transform(chunk,controller){
      if(offset+chunk.length>buffer.length){
        const newSize=Math.max(buffer.length*2,offset+chunk.length);
        const newBuffer=new Uint8Array(newSize);
        newBuffer.set(buffer.subarray(0,offset));
        buffer=newBuffer;
      }
      buffer.set(chunk,offset);
      offset+=chunk.length;
      if(offset>=CONFIG.maxBufferSize){
        if(CONFIG.enableHybridDrive){
          flushBuffer(controller);
          if(timerId)clearTimeout(timerId);timerId=null;
        }else{
          return new Promise(resolve=>resolveResumeSignal=resolve);
        }
      }else if(CONFIG.enableHybridDrive){
        if(timerId)clearTimeout(timerId);
        timerId=setTimeout((0)=>flushBuffer(controller),CONFIG.flushTimeoutMs);
      }
    },
    flush(controller){
      if(CONFIG.enableHybridDrive){if(timerId)clearTimeout(timerId);}
      else{if(timerId)clearInterval(timerId);if(resolveResumeSignal)resolveResumeSignal();}
      flushBuffer(controller);
    }
  });
};
const handleWebSocketConn=async(request)=>{
  const{0:clientSocket,1:webSocket}=new WebSocketPair();
  webSocket.accept();
  const protocolHeader=request.headers.get('sec-websocket-protocol');
  const earlyData=protocolHeader?Uint8Array.fromBase64(protocolHeader,{alphabet:'base64url'}):null;
  let messageHandler,tcpSocket;
  let socks5State=0;
  const closeSocket=()=>{tcpSocket?.close();if(!earlyData)webSocket?.close();};
  if(earlyData)await processChunk(earlyData).catch(()=>closeSocket());
  webSocket.addEventListener("message",async(event)=>await processChunk(event.data).catch(()=>closeSocket()));
  async function processChunk(chunk){
    if(messageHandler)return messageHandler(chunk);
    chunk=chunk instanceof Uint8Array?chunk:new Uint8Array(chunk);
    if(socks5State===1){
        if(chunk.length>2&&chunk[0]===0x01){
            try{
                let offset=1;
                const uLen=chunk[offset++];
                const user=new TextDecoder().decode(chunk.subarray(offset,offset+uLen));
                offset+=uLen;
                const pLen=chunk[offset++];
                const pass=new TextDecoder().decode(chunk.subarray(offset,offset+pLen));
                if(user===CONFIG.uuid&&pass===CONFIG.password){
                    webSocket.send(new Uint8Array([1,0]));
                    socks5State=2;
                    return;
                }
            }catch{}
        }
        webSocket.send(new Uint8Array([1,1]));
        closeSocket();
        return;
    }
    let parsedRequest;
    if(chunk[0]===5){
      if(socks5State===0){
        webSocket.send(new Uint8Array([5,1]));
        socks5State=1;
        return;
      }
      if(socks5State===2&&chunk[1]===1)parsedRequest=parseSocks5(chunk);
    }else if(socks5State===0){
        if(chunk.length>58&&chunk[56]===0x0d&&chunk[57]===0x0a){parsedRequest=parseTransparent(chunk);}
        else if((parsedRequest=parseRequestData(chunk))){webSocket.send(new Uint8Array([chunk[0],0]));}
        else{parsedRequest=parseShadow(chunk);}
    }
    if(!parsedRequest)throw new Error();
    const payload=chunk.subarray(parsedRequest.dataOffset);
    if(parsedRequest.isDns){
      await dohDnsHandler(webSocket,!!earlyData,payload);
    }else{
      tcpSocket=await establishTcpConnection(parsedRequest,request);
      if(!tcpSocket)throw new Error();
      if(parsedRequest.isSocks5)webSocket.send(new Uint8Array([5,0,0,1,0,0,0,0,0,0]));
      const tcpWriter=tcpSocket.writable.getWriter();
      if(payload.byteLength)await tcpWriter.write(payload);
      const webSocketWriter=new WritableStream({write:chunk=>webSocket.send(chunk)});
      CONFIG.userBufferer?tcpSocket.readable.pipeThrough(createBufferer()).pipeTo(webSocketWriter):tcpSocket.readable.pipeTo(webSocketWriter);
      messageHandler=(chunk)=>tcpWriter.write(chunk);
    }
  }
  return new Response(null,{status:101,webSocket:clientSocket});
};
const handleXhttp=async(request)=>{
  const reader=request.body.getReader();
  let buffer=new Uint8Array(4096),used=0,parsedRequest=null;
  while(true){
    const{value,done}=await reader.read();
    if(done)return new Response(null,{status:500});
    if(used+value.length>buffer.length){
      const newBuffer=new Uint8Array(Math.max(buffer.length*2,used+value.length));
      newBuffer.set(buffer.subarray(0,used));
      buffer=newBuffer;
    }
    buffer.set(value,used);
    used+=value.length;
    if(used<48)continue;
    const currentBuffer=buffer.subarray(0,used);
    parsedRequest=parseRequestData(currentBuffer);
    if(parsedRequest)break;
  }
  const tcpSocket=await establishTcpConnection(parsedRequest,request);
  if(!tcpSocket)return new Response(null,{status:500});
  const payload=buffer.subarray(parsedRequest.dataOffset,used);
  const requestToTcp=async()=>{
    const writer=tcpSocket.writable.getWriter();
    if(payload.byteLength)await writer.write(payload);
    writer.releaseLock();
    reader.releaseLock();
    await request.body.pipeTo(tcpSocket.writable);
  };
  requestToTcp().catch(()=>tcpSocket.close());
  const resVersion=new Uint8Array([buffer[0],0]);
  const tcpToResponse=new TransformStream({
    start(controller){controller.enqueue(resVersion);},
    transform(chunk,controller){controller.enqueue(chunk);}
  });
  const bufferer=createBufferer(resVersion);
  const responseStream=CONFIG.userBufferer?tcpSocket.readable.pipeThrough(bufferer):tcpSocket.readable.pipeThrough(tcpToResponse);
  return new Response(responseStream,{headers:{'Content-Type':'application/octet-stream','X-Accel-Buffering':'no','Cache-Control':'no-store'}});
};
function getCommonNodeInfo(request){
    const url=new URL(request.url);
    const host=url.hostname;
    const ports=[443];
    const ws_path="/?ed=2560";
    const xhttp_path="/"+CONFIG.uuid.substring(0,8);
    return{host,ports,ws_path,xhttp_path,url};
}
function generateNodeLinks(host,ports,encoded_ws_path,encoded_xhttp_path){
    const links=[];
    ports.forEach(port=>{
        links.push(`vless://${CONFIG.uuid}@${host}:${port}?encryption=none&security=tls&sni=${host}&alpn=http%2F1.1&fp=chrome&type=ws&host=${host}&path=${encoded_ws_path}#${encodeURIComponent(`VLESS-WS-${host}-${port}`)}`);
        links.push(`vless://${CONFIG.uuid}@${host}:${port}?encryption=none&security=tls&sni=${host}&fp=random&allowInsecure=1&type=xhttp&host=${host}&path=${encoded_xhttp_path}&mode=stream-one#${encodeURIComponent(`VLESS-HTTP-${host}-${port}`)}`);
        links.push(`trojan://${CONFIG.password}@${host}:${port}?security=tls&sni=${host}&alpn=http%2F1.1&fp=chrome&allowInsecure=1&type=ws&host=${host}&path=${encoded_ws_path}#${encodeURIComponent(`Trojan-WS-${host}-${port}`)}`);
        links.push(`socks://${CONFIG.uuid}:${CONFIG.password}@${host}:${port}#${encodeURIComponent(`Socks5-WS-${host}-${port}`)}`);
    });
    return links;
}
function generateSubData(request){
    const{host,ports,ws_path,xhttp_path}=getCommonNodeInfo(request);
    const nodeLinks=generateNodeLinks(host,ports,encodeURIComponent(ws_path),encodeURIComponent(xhttp_path));
    const ssLinks=[];
    const ss_b64=btoa(`none:${CONFIG.password}`);
    const plugin=encodeURIComponent(`v2ray-plugin;tls;host=${host};path=${ws_path}`);
    ports.forEach(port=>{
       ssLinks.push(`ss://${ss_b64}@${host}:${port}/?plugin=${plugin}#${encodeURIComponent(`Shadowsocks-WS-${host}-${port}`)}`);
    });
    const allLinks=[...nodeLinks,....ssLinks];
    return btoa(unescape(encodeURIComponent(allLinks.join('\n'))));
}
function handleAdminPage(request){
  const{host,ports,ws_path,xhttp_path,url}=getCommonNodeInfo(request);
  const sub_url=`${url.protocol}//${host}/${CONFIG.password}`;
  const node_links=generateNodeLinks(host,ports,encodeURIComponent(ws_path),encodeURIComponent(xhttp_path));
  const ss_base=btoa(`none:${CONFIG.password}`);
  const ss_links=ports.map(port=>`ss://${ss_base}@${host}:${port}#${encodeURIComponent(`Shadowsocks-WS-${host}-${port}`)}`);
  const html=`<!DOCTYPE html><html><head><title>节点管理</title><meta charset="UTF-8"><style>body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; background-color: #f5f5f5; color: #333; } .container { max-width: 800px; margin: 30px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); } h2 { border-bottom: 2px solid #3498db; padding-bottom: 10px; color: #2c3e50; margin-top: 0;} h3 { color: #2980b9; margin-top: 25px; } .code-block { background-color: #f8f9fa; padding: 10px; border-radius: 5px; border: 1px solid #e9ecef; font-family: monospace; word-break: break-all; font-size: 0.9em; margin-bottom: 10px; } .btn { display: inline-block; padding: 8px 16px; background-color: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; transition: background 0.2s; font-size: 14px; } .btn:hover { background-color: #2980b9; } .warning { background-color: #fff3cd; color: #856404; padding: 12px; border-radius: 4px; border: 1px solid #ffeeba; margin-bottom: 15px; }</style></head><body><div class="container"><h2>节点订阅</h2><p>请将以下链接添加至您的客户端：</p><div class="code-block" id="sub-url">${sub_url}</div><button class="btn" onclick="copy('sub-url')">复制订阅链接</button><h3>单独节点 (VLESS / Trojan / Socks5)</h3>${node_links.map(l=>`<div class="code-block">${l}</div>`).join('')}<h3>Shadowsocks (SS)</h3><div class="warning">⚠️ SS 节点需手动配置插件信息：<br><b>Plugin:</b> v2ray-plugin<br><b>Options:</b> ws;host=${host};path=${ws_path}</div>${ss_links.map(l=>`<div class="code-block">${l}</div>`).join('')}</div><script>function copy(id) { const text = document.getElementById(id).innerText; navigator.clipboard.writeText(text).then(() => alert('已复制！')).catch(err => alert('复制失败')); }</script></body></html>`;
  return new Response(html,{headers:{'Content-Type':'text/html; charset=utf-8'}});
}
export default{
  async fetch(request){
    const url=new URL(request.url);
    if(url.pathname===`/${CONFIG.password}`){ 
      return new Response(generateSubData(request),{headers:{'Content-Type':'text/plain;charset=utf-8'}});
    }
    if(url.pathname===`/${CONFIG.password}-admin`){
      return handleAdminPage(request);
    }
    if(request.method==='POST')return handleXhttp(request);
    if(request.headers.get('Upgrade')?.toLowerCase()==='websocket'){
      return handleWebSocketConn(request);
    }
    return new Response(CONFIG.maintainHtml,{status:200,headers:{'Content-Type':'text/html; charset=UTF-8'}});
  }
};
