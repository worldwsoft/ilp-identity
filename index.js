import { createDID as createKeyDID, resolveDID as resolveKeyDID, } from './did.key.js'
import { DidError } from './error.js'


async function createDID(options = {}){
	const method = options.method ?? 'key'

	switch (method){
		case 'key': 
			return await createKeyDID()
		default:
			throw new Error(`Unsupported DID method "${method}"`)
	}
}

async function resolveDID(did){
	const [scheme, method, id] = did.split(':')

	if(scheme !== 'did' || !method || !id)
		throw new DidError('Not a valid DID')

	switch (method){
		case 'key':
			return resolveKeyDID(did)
		default:
			throw new DidError(`Unsupported DID method "${method}" for DID "${did}"`)
	}
}

export {
	createDID,
	resolveDID,
	DidError
}
