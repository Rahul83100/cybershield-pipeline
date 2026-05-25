const base64 = Buffer.from('HelloWorld🔥').toString('base64');
function decodeBase64Utf8(base64) {
    const raw = atob(base64);
    const bytes = new Uint8Array(raw.length);
    for(let i = 0; i < raw.length; i++) { bytes[i] = raw.charCodeAt(i); }
    return new TextDecoder().decode(bytes);
}
console.log(decodeBase64Utf8(base64));
