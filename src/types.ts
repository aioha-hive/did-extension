import type { Aioha, Providers, KeyTypes } from '@aioha/aioha'

export interface Context {
  aioha: Aioha
  keyType: KeyTypes
  defaultProv?: Providers
  defaultPub?: string
}

export interface DIDHiveKeyAuth {
  pubkey: string
  did: string
  threshold: number
}

interface HiveKeyAuths {
  key_auths: [string, number][]
}

export interface AccountKeyAuthResult {
  name: string
  owner: HiveKeyAuths
  active: HiveKeyAuths
  posting: HiveKeyAuths
}

export interface Defaults {
  provider?: Providers
  pubKey?: string
}
