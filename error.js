export class DidError extends Error{
	constructor(message){
		super(message)
		this.name = 'DidKeyError'
	}
}