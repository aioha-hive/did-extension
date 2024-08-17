/**
 * Key DID provider adopted for Aioha
 * https://github.com/ceramicnetwork/js-did/blob/main/packages/key-did-provider-secp256k1/src/index.ts
 */
import { createJWS } from 'did-jwt'
import type { AuthParams, CreateJWSParams, DIDMethodName, DIDProviderMethods, DIDProvider, GeneralJWS } from 'dids'
import stringify from 'fast-json-stable-stringify'
import { createHandler } from 'rpc-utils'
import type { RPCRequest, RPCResponse, SendRequestFunc } from 'rpc-utils'
import bs58 from 'bs58'
import * as u8a from 'uint8arrays'
import { sha256 as sha256Hash } from '@noble/hashes/sha256'
import { Signature } from '@noble/secp256k1'
import type { AiohaOperations } from '@aioha/aioha/build/providers/provider.js'
import { Aioha, Providers, KeyTypes } from '@aioha/aioha'
import { AiohaRpcError } from '@aioha/aioha/build/jsonrpc/eip1193-types.js'
import { Context, DIDHiveKeyAuth, AccountKeyAuthResult, Defaults } from './types.js'
import { toJose, leftpad } from './utils.js'

function toStableObject(obj: Record<string, any>): Record<string, any> {
  return JSON.parse(stringify(obj)) as Record<string, any>
}

export function encodeDIDFromPub(publicKey: string): string {
  const decoded = bs58.decode(publicKey.slice(3)).slice(0, -4)
  const bytes = new Uint8Array(decoded.length + 2)
  bytes[0] = 0xe7 // secp256k1 multicodec
  // The multicodec is encoded as a varint so we need to add this.
  // See js-multicodec for a general implementation
  bytes[1] = 0x01
  bytes.set(decoded, 2)
  return `did:key:z${u8a.toString(bytes, 'base58btc')}`
}

function toGeneralJWS(jws: string): GeneralJWS {
  const [protectedHeader, payload, signature] = jws.split('.')
  return {
    payload,
    signatures: [{ protected: protectedHeader, signature }]
  }
}

function uint8ArrayToHexString(uint8Array: Uint8Array) {
  // Convert each byte to a two-digit hexadecimal string
  return Array.from(uint8Array)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

function hexToUint8Array(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string')
  const arrayBuffer = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    arrayBuffer[i / 2] = parseInt(hex.substring(i, i + 2), 16)
  }
  return arrayBuffer
}

function parseSignature(sig: string) {
  const uint8Array = hexToUint8Array(sig)
  if (uint8Array.length !== 65) throw new Error('Invalid signature')
  const recovery = uint8Array[0] - 31
  const data = uint8Array.slice(1)
  return {
    recovery,
    data
  }
}

function sha256(payload: string | Uint8Array): string {
  const data = typeof payload === 'string' ? u8a.fromString(payload) : payload
  return uint8ArrayToHexString(sha256Hash(data))
}

const AiohaSigner = (aioha: AiohaOperations, keyType: KeyTypes, recoverable = false) => {
  return async (data: string | Uint8Array): Promise<string> => {
    const signResult = await aioha.signMessage(sha256(data), keyType)
    if (!signResult.success) throw new AiohaRpcError(signResult.errorCode, signResult.error)
    const u8aSig = parseSignature(signResult.result)
    const parsedSig = Signature.fromCompact(u8aSig.data).addRecoveryBit(u8aSig.recovery)
    return toJose(
      {
        r: leftpad(parsedSig.r.toString(16)),
        s: leftpad(parsedSig.s.toString(16)),
        recoveryParam: parsedSig.recovery
      },
      recoverable
    )
  }
}

const sign = async (
  payload: Record<string, any> | string,
  aioha: Aioha,
  keyType: KeyTypes,
  protectedHeader: Record<string, any> = {}
) => {
  const did = encodeDIDFromPub(aioha.getPublicKey()!)
  const kid = `${did}#${did.split(':')[2]}`
  const signer = AiohaSigner(aioha, keyType)
  const header = toStableObject(Object.assign(protectedHeader, { kid, alg: 'ES256K' }))

  return createJWS(typeof payload === 'string' ? payload : toStableObject(payload), signer, header)
}

const didMethods = {
  did_authenticate: async ({ aioha, keyType }: Context, params: AuthParams) => {
    const pub = aioha.getPublicKey()
    if (!pub) throw new AiohaRpcError(4100, 'could not retrieve DID due to no public key')
    const did = encodeDIDFromPub(pub)
    // TODO: Call Aioha login()
    const response = await sign(
      {
        did,
        aud: params.aud,
        nonce: params.nonce,
        paths: params.paths,
        exp: Math.floor(Date.now() / 1000) + 600 // expires 10 min from now
      },
      aioha,
      keyType
    )
    return toGeneralJWS(response)
  },
  did_createJWS: async ({ aioha, keyType }: Context, params: CreateJWSParams & { did: string }) => {
    const pub = aioha.getPublicKey()
    if (!pub) throw new AiohaRpcError(4100, 'could not retrieve DID due to no public key')
    const did = encodeDIDFromPub(pub)
    const requestDid = params.did.split('#')[0]
    if (requestDid !== did) throw new AiohaRpcError(4100, `Unknown DID: ${did}`)
    const jws = await sign(params.payload, aioha, keyType, params.protected)
    return { jws: toGeneralJWS(jws) }
  },
  did_decryptJWE: async () => {
    throw new AiohaRpcError(4200, 'Decryption not supported')
  }
}

export class AiohaDID implements DIDProvider {
  _handle?: SendRequestFunc<DIDProviderMethods>
  aioha: Aioha
  keyType: KeyTypes = KeyTypes.Posting
  defaults: Defaults = {}

  constructor(aioha: Aioha) {
    this.aioha = aioha
    const handler = createHandler<Context, DIDProviderMethods>(didMethods)
    this._handle = async (msg) =>
      await handler(
        { aioha, keyType: this.getKeyType(), defaultProv: this.getDefaults().provider, defaultPub: this.getDefaults().pubKey },
        msg
      )
  }

  get isDidProvider(): boolean {
    return true
  }

  /**
   * Set default provider for login when used in `dids` library.
   * @param prov
   */
  setDefaultProvider(prov?: Providers) {
    this.defaults.provider = prov
  }

  /**
   * Set default public key used to create JWS when `aioha.getPublicKey()` returns undefined.
   * @param pubKey
   */
  setDefaultPubKey(pubKey?: string) {
    this.defaults.pubKey = pubKey
  }

  setKeyType(keyType: KeyTypes) {
    this.keyType = keyType
  }

  getKeyType() {
    return this.keyType
  }

  getDefaults() {
    return this.defaults
  }

  getDid() {
    return encodeDIDFromPub(this.aioha.getPublicKey()!)
  }

  async fetchPubKeysWithDID(usernames: string[]) {
    const accounts = (await this.aioha.request({
      method: 'condenser_api.get_accounts',
      params: [usernames]
    })) as AccountKeyAuthResult[]
    const result: {
      [user: string]: {
        owner: DIDHiveKeyAuth[]
        active: DIDHiveKeyAuth[]
        posting: DIDHiveKeyAuth[]
      }
    } = {}
    const p = (val: [string, number]) => {
      return {
        pubkey: val[0],
        did: encodeDIDFromPub(val[0]),
        threshold: val[1]
      }
    }
    for (const a in accounts) {
      result[accounts[a].name] = {
        owner: accounts[a].owner.key_auths.map(p),
        active: accounts[a].active.key_auths.map(p),
        posting: accounts[a].posting.key_auths.map(p)
      }
    }
    return result
  }

  async send<Name extends DIDMethodName>(
    msg: RPCRequest<DIDProviderMethods, Name>
  ): Promise<RPCResponse<DIDProviderMethods, Name> | null> {
    return await this._handle!(msg)
  }
}
