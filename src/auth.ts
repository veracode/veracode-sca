const sjcl = require('sjcl');
const util = require('util');
const crypto = require('crypto');

module.exports.calculateAuthorizationHeader = calculateAuthorizationHeader;

const authorizationScheme = "VERACODE-HMAC-SHA-256";
const requestVersion = "vcode_request_version_1";
const nonceSize = 16;

function computeHashHex(message:any, key_hex:any) {
    let key_bits = sjcl.codec.hex.toBits(key_hex);
    let hmac_bits = (new sjcl.misc.hmac(key_bits, sjcl.hash.sha256)).mac(message);
    let hmac = sjcl.codec.hex.fromBits(hmac_bits);
    return hmac;
}

function calulateDataSignature(apiKeyBytes:any, nonceBytes:any, dateStamp:any, data:any) {
    let kNonce = computeHashHex(nonceBytes, apiKeyBytes);
    let kDate = computeHashHex(dateStamp, kNonce);
    let kSig = computeHashHex(requestVersion, kDate);
    let kFinal = computeHashHex(data, kSig);
    return kFinal;
}

function newNonce(nonceSize:any) {
    return crypto.randomBytes(nonceSize).toString('hex').toUpperCase();
}

function toHexBinary(input:any) {
    return sjcl.codec.hex.fromBits(sjcl.codec.utf8String.toBits(input));
}

export function calculateAuthorizationHeader(id:string, key:string, hostName:string, uriString:string, httpMethod:string) {
    let data = `id=${id}&host=${hostName}&url=${uriString}&method=${httpMethod}`;
    let dateStamp = Date.now().toString();
    let nonceBytes = newNonce(nonceSize);
    let dataSignature = calulateDataSignature(key, nonceBytes, dateStamp, data);
    let authorizationParam = `id=${id},ts=${dateStamp},nonce=${toHexBinary(nonceBytes)},sig=${dataSignature}`;
    let header = authorizationScheme + " " + authorizationParam;
    return header;
}






/*
import crypto from 'crypto';

const preFix = "VERACODE-HMAC-SHA-256";
const verStr = "vcode_request_version_1";

function hmac256(data:any, key:any, format:any){
	var hash = crypto.createHmac('sha256', key).update(data);
	// no format = Buffer / byte array
	return hash.digest(format);
}

function getByteArray(hex:any) {
	var bytes = [];

	for(var i = 0; i < hex.length-1; i+=2){
	    bytes.push(parseInt(hex.substr(i, 2), 16));
	}

	// signed 8-bit integer array (byte array)
	return Int8Array.from(bytes);
}

export function generateHeader(url:string, method:string, host:string, id:string, key:string) {

	var data = `id=${id}&host=${host}&url=${url}&method=${method}`;
	var timestamp = (new Date().getTime()).toString();
	var nonce = crypto.randomBytes(16).toString("hex");

	// calculate signature
	var hashedNonce = hmac256(getByteArray(nonce), getByteArray(key), null)
	var hashedTimestamp = hmac256(timestamp, hashedNonce, null)
	var hashedVerStr = hmac256(verStr, hashedTimestamp, null);
	var signature = hmac256(data, hashedVerStr, 'hex');

	return `${preFix} id=${id},ts=${timestamp},nonce=${nonce},sig=${signature}`;
}
*/