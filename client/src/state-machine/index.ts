import { PeerEntry } from "./peer-state";
import { State } from "./machine";

export enum Phase {
  KEYGEN = "keygen",
  SIGN = "sign",
}

// Configuration parameters retrieved from the server
// during the handshake.
export interface Parameters {
  parties: number;
  threshold: number;
}

// Private key share for GG2020.
export interface KeyShare {
  localKey: LocalKey;
  publicKey: number[];
  address: string;
}

// Opaque type for the private key share.
export interface LocalKey {}

// Generated by the server to signal this party wants
// to be included in key generation.
//
// The uuid is injected from the session that owns
// this party signup.
export interface PartySignup {
  number: number;
  uuid: string;
}

export interface Session {
  uuid: string;
  partySignup?: PartySignup;
}

/*
// Temporary object passed back and forth between javascript
// and webassembly for the various rounds.
export interface RoundEntry {
  peer_entries: PeerEntry[];
  // Webassembly adds a bunch of temporary properties
  // to each round entry for further rounds but
  // these fields should not be accessed here
  // however we declare their presence in the type
  [x: string]: any;
}
*/

// State for party signup round during keygen.
export interface PartySignupInfo {
  parameters: Parameters;
  partySignup: PartySignup;
}

export interface SessionInfo {
  groupId: string;
  sessionId: string;
  parameters: Parameters;
  partySignup: PartySignup;
}

export interface SignResult {
  r: string;
  s: string;
  recid: number;
}

export interface SignMessage {
  result: SignResult;
  public_key: number[];
  address: string;
}

export function makeOnTransition<T, U>() {
  return (
    index: number,
    previousState: State<T, U>,
    nextState: State<T, U>
  ) => {
    let message = "";
    if (previousState) {
      message = `transition ${index} from ${previousState.name} to ${nextState.name}`;
    } else {
      message = `transition ${index} to ${nextState.name}`;
    }
    console.log(message);
  };
}
