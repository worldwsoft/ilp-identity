import { webcrypto } from 'node:crypto';

const crypto = globalThis.crypto ?? webcrypto;

const DID_CONTEXT = 'https://www.w3.org/ns/did/v1';
const DID_CONTEXT_V11 = 'https://www.w3.org/ns/did/v1.1';
const DID_KEY_PREFIX = 'did:key:';
const ED25519_MULTICODEC = 0xed;
const ED25519_PUBLIC_KEY_LENGTH = 32;
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const BASE58_LOOKUP = new Map(
	[...BASE58_ALPHABET].map((character, index) => [character, index]),
);

function assertWebCrypto() {
	if (!crypto?.subtle) {
		throw new DidKeyError(
			'WebCrypto is not available in this runtime.',
			'ERR_WEBCRYPTO_UNAVAILABLE',
		);
	}
}

function encodeBase64Url(bytes) {
	return Buffer.from(bytes).toString('base64url');
}

function decodeBase64Url(value) {
	try {
		return new Uint8Array(Buffer.from(value, 'base64url'));
	} catch {
		throw new DidKeyError('Invalid base64url value.', 'ERR_INVALID_BASE64URL');
	}
}

function concatBytes(...arrays) {
	const totalLength = arrays.reduce((sum, array) => sum + array.length, 0);
	const result = new Uint8Array(totalLength);
	let offset = 0;

	for (const array of arrays) {
		result.set(array, offset);
		offset += array.length;
	}

	return result;
}

function encodeVarint(value) {
	if (!Number.isInteger(value) || value < 0) {
		throw new DidKeyError('Invalid varint value.', 'ERR_INVALID_VARINT');
	}

	const output = [];
	let remaining = value;

	while (remaining >= 0x80) {
		output.push((remaining & 0x7f) | 0x80);
		remaining >>>= 7;
	}

	output.push(remaining);
	return Uint8Array.from(output);
}

function decodeVarint(bytes) {
	let value = 0;
	let shift = 0;

	for (let index = 0; index < bytes.length; index += 1) {
		const byte = bytes[index];
		value |= (byte & 0x7f) << shift;

		if ((byte & 0x80) === 0) {
			return {
				value,
				byteLength: index + 1,
			};
		}

		shift += 7;

		if (shift > 35) {
			break;
		}
	}

	throw new DidKeyError('Invalid multicodec varint.', 'ERR_INVALID_MULTICODEC');
}

function encodeBase58(bytes) {
	if (bytes.length === 0) {
		return '';
	}

	let zeros = 0;
	while (zeros < bytes.length && bytes[zeros] === 0) {
		zeros += 1;
	}

	let value = 0n;
	for (const byte of bytes) {
		value = (value << 8n) + BigInt(byte);
	}

	let encoded = '';
	while (value > 0n) {
		const remainder = Number(value % 58n);
		value /= 58n;
		encoded = BASE58_ALPHABET[remainder] + encoded;
	}

	return '1'.repeat(zeros) + encoded;
}

function decodeBase58(value) {
	if (value.length === 0) {
		return new Uint8Array();
	}

	let zeros = 0;
	while (zeros < value.length && value[zeros] === '1') {
		zeros += 1;
	}

	let decoded = 0n;
	for (const character of value) {
		const digit = BASE58_LOOKUP.get(character);
		if (digit === undefined) {
			throw new DidKeyError('Invalid base58btc value.', 'ERR_INVALID_BASE58');
		}

		decoded = (decoded * 58n) + BigInt(digit);
	}

	const bytes = [];
	while (decoded > 0n) {
		bytes.push(Number(decoded & 0xffn));
		decoded >>= 8n;
	}

	bytes.reverse();
	return Uint8Array.from([...new Array(zeros).fill(0), ...bytes]);
}

function encodeMultibaseBase58(bytes) {
	return `z${encodeBase58(bytes)}`;
}

function decodeMultibaseValue(multibaseValue) {
	if (typeof multibaseValue !== 'string' || multibaseValue.length < 2) {
		throw new DidKeyError('Invalid multibase public key.', 'ERR_INVALID_MULTIBASE');
	}

	const prefix = multibaseValue[0];
	const body = multibaseValue.slice(1);

	if (prefix === 'z') {
		return decodeBase58(body);
	}

	if (prefix === 'u') {
		return decodeBase64Url(body);
	}

	throw new DidKeyError(
		'Unsupported multibase encoding for did:key.',
		'ERR_UNSUPPORTED_MULTIBASE',
	);
}

function parseDid(did) {
	if (typeof did !== 'string') {
		throw new DidKeyError('DID must be a string.', 'ERR_INVALID_DID');
	}

	const components = did.split(':');

	if (components.length !== 3 && components.length !== 4) {
		throw new DidKeyError('Invalid did:key identifier.', 'ERR_INVALID_DID');
	}

	const [scheme, method] = components;
	const version = components.length === 4 ? components[2] : '1';
	const multibaseValue = components.at(-1);

	if (scheme !== 'did' || method !== 'key') {
		throw new DidKeyError('Invalid did:key identifier.', 'ERR_INVALID_DID');
	}

	if (!/^\d+$/.test(version) || Number(version) <= 0) {
		throw new DidKeyError('Invalid did:key version.', 'ERR_INVALID_DID');
	}

	return {
		did,
		multibaseValue,
	};
}

function getEd25519PublicJwk(publicKeyBytes) {
	if (publicKeyBytes.length !== ED25519_PUBLIC_KEY_LENGTH) {
		throw new DidKeyError(
			'Invalid Ed25519 public key length.',
			'ERR_INVALID_PUBLIC_KEY_LENGTH',
		);
	}

	return {
		kty: 'OKP',
		crv: 'Ed25519',
		x: encodeBase64Url(publicKeyBytes),
	};
}

function getVerificationMethodId(did, multibaseValue) {
	return `${did}#${multibaseValue}`;
}

/**
 * Generate a new Ed25519 did:key identifier.
 *
 * @returns {Promise<{did: string, privateKey: JsonWebKey}>}
 */
export async function createDID() {
	assertWebCrypto();

	const keyPair = await crypto.subtle.generateKey(
		{ name: 'Ed25519' },
		true,
		['sign', 'verify'],
	);

	const [privateKey, publicKey] = await Promise.all([
		crypto.subtle.exportKey('jwk', keyPair.privateKey),
		crypto.subtle.exportKey('jwk', keyPair.publicKey),
	]);

	if (
		publicKey.kty !== 'OKP'
		|| publicKey.crv !== 'Ed25519'
		|| typeof publicKey.x !== 'string'
	) {
		throw new DidKeyError(
			'Unexpected public key format returned by WebCrypto.',
			'ERR_INVALID_PUBLIC_KEY',
		);
	}

	const publicKeyBytes = decodeBase64Url(publicKey.x);
	const multicodecBytes = concatBytes(
		encodeVarint(ED25519_MULTICODEC),
		publicKeyBytes,
	);
	const multibaseValue = encodeMultibaseBase58(multicodecBytes);

	return {
		did: `${DID_KEY_PREFIX}${multibaseValue}`,
		privateKey,
	};
}

/**
 * Resolve an Ed25519 did:key identifier into a minimal DID document.
 *
 * @param {string} did
 * @returns {{
 *   '@context': string[],
 *   id: string,
 *   verificationMethod: Array<{
 *     id: string,
 *     type: 'JsonWebKey',
 *     controller: string,
 *     publicKeyJwk: JsonWebKey,
 *   }>,
 *   authentication: string[],
 *   assertionMethod: string[],
 *   capabilityInvocation: string[],
 *   capabilityDelegation: string[],
 * }}
 */
export function resolveDID(did) {
	const { multibaseValue } = parseDid(did);
	const decodedKey = decodeMultibaseValue(multibaseValue);
	const { value: multicodec, byteLength } = decodeVarint(decodedKey);
	const publicKeyBytes = decodedKey.slice(byteLength);

	if (multicodec !== ED25519_MULTICODEC) {
		throw new DidKeyError(
			'Only Ed25519 did:key identifiers are supported.',
			'ERR_UNSUPPORTED_KEY_TYPE',
		);
	}

	const verificationMethodId = getVerificationMethodId(did, multibaseValue);

	return {
		'@context': [DID_CONTEXT, DID_CONTEXT_V11],
		id: did,
		verificationMethod: [
			{
				id: verificationMethodId,
				type: 'JsonWebKey',
				controller: did,
				publicKeyJwk: getEd25519PublicJwk(publicKeyBytes),
			},
		],
		authentication: [verificationMethodId],
		assertionMethod: [verificationMethodId],
		capabilityInvocation: [verificationMethodId],
		capabilityDelegation: [verificationMethodId],
	};
}

export default {
	createDID,
	resolveDID,
};
