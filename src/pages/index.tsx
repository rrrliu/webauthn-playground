import { Client, UserOperationBuilder } from "userop";
import {
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";
import base64 from "@hexagon/base64";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  VerifiedRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import * as cborx from "cbor-x";
import { useState } from "react";
import { AsnParser } from "@peculiar/asn1-schema";
import { ECDSASigValue } from "@peculiar/asn1-ecc";
import axios from "axios";
import Image from "next/image";

const encoder = new cborx.Encoder({
  mapsAsObjects: false,
  tagUint8Array: false,
});

export function decodeFirst<Type>(input: Uint8Array): Type {
  const decoded = encoder.decodeMultiple(input) as undefined | Type[];

  if (decoded === undefined) {
    throw new Error("CBOR input data was empty");
  }

  /**
   * Typing on `decoded` is `void | []` which causes TypeScript to think that it's an empty array,
   * and thus you can't destructure it. I'm ignoring that because the code works fine in JS, and
   * so this should be a valid operation.
   */
  // @ts-ignore 2493
  const [first] = decoded;

  return first;
}

function toDataView(array: Uint8Array): DataView {
  return new DataView(array.buffer, array.byteOffset, array.length);
}

export function parseAuthenticatorData(authData: Uint8Array) {
  if (authData.byteLength < 37) {
    throw new Error(
      `Authenticator data was ${authData.byteLength} bytes, expected at least 37 bytes`
    );
  }

  let pointer = 0;
  const dataView = toDataView(authData);

  const rpIdHash = authData.slice(pointer, (pointer += 32));

  const flagsBuf = authData.slice(pointer, (pointer += 1));
  const flagsInt = flagsBuf[0];

  // Bit positions can be referenced here:
  // https://www.w3.org/TR/webauthn-2/#flags
  const flags = {
    up: !!(flagsInt & (1 << 0)), // User Presence
    uv: !!(flagsInt & (1 << 2)), // User Verified
    be: !!(flagsInt & (1 << 3)), // Backup Eligibility
    bs: !!(flagsInt & (1 << 4)), // Backup State
    at: !!(flagsInt & (1 << 6)), // Attested Credential Data Present
    ed: !!(flagsInt & (1 << 7)), // Extension Data Present
    flagsInt,
  };

  const counterBuf = authData.slice(pointer, pointer + 4);
  const counter = dataView.getUint32(pointer, false);
  pointer += 4;

  let aaguid: Uint8Array | undefined = undefined;
  let credentialID: Uint8Array | undefined = undefined;
  let credentialPublicKey: Uint8Array | undefined = undefined;
  let credentialPublicKeyDecoded: Uint8Array | undefined = undefined;

  if (flags.at) {
    aaguid = authData.slice(pointer, (pointer += 16));

    const credIDLen = dataView.getUint16(pointer);
    pointer += 2;

    credentialID = authData.slice(pointer, (pointer += credIDLen));

    // Decode the next CBOR item in the buffer, then re-encode it back to a Buffer
    const firstDecoded = decodeFirst(authData.slice(pointer));
    const firstEncoded = Uint8Array.from(encoder.encode(firstDecoded));

    credentialPublicKey = firstEncoded;
    credentialPublicKeyDecoded = firstDecoded as any;
    pointer += firstEncoded.byteLength;
  }

  return {
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
    aaguid,
    credentialID,
    credentialPublicKey,
    credentialPublicKeyDecoded,
  };
}

function concatUint8Arrays(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

function shouldRemoveLeadingZero(bytes: Uint8Array): boolean {
  return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0;
}

export default function Home() {
  const API_URL =
    process.env.NODE_ENV === "production"
      ? "https://proving-server.onrender.com/"
      : "http://localhost:8000";
  const [username, setUsername] = useState("");
  const [response, setResponse] = useState<VerifiedRegistrationResponse>();
  const [proof, setProof] = useState("");
  const [loading, setLoading] = useState(false);
  const [verified, setVerified] = useState<boolean>();
  const [verifyLoading, setVerifyLoading] = useState(false);

  async function loginCredential() {
    const authenticationOptions = await generateAuthenticationOptions({
      rpID: window.location.hostname,
      challenge: "asdf",
    });
    const authenticationResponse = await startAuthentication(
      authenticationOptions
      // await browserSupportsWebAuthnAutofill()
    );
    const clientDataJSON = base64.toArrayBuffer(
      authenticationResponse.response.clientDataJSON,
      true
    );
    const authenticatorData = base64.toArrayBuffer(
      authenticationResponse.response.authenticatorData,
      true
    );
    const signature = base64.toArrayBuffer(
      authenticationResponse.response.signature,
      true
    );
    const parsed = parseAuthenticatorData(new Uint8Array(authenticatorData));

    const hashedClientData = await window.crypto.subtle.digest(
      "SHA-256",
      clientDataJSON
    );
    const preimage = concatUint8Arrays(
      new Uint8Array(authenticatorData),
      new Uint8Array(hashedClientData)
    );
    const hashedMessage = await window.crypto.subtle.digest(
      "SHA-256",
      preimage
    );

    console.log({
      clientDataJSON,
      authenticationOptions,
      authenticationResponse,
      parsed,
      hashedMessage,
      hashedClientData,
      preimage,
      signature: new Uint8Array(signature),
    });

    const fetched = localStorage.getItem(authenticationResponse.id);
    if (!fetched) {
      throw new Error(`Not stored for ${authenticationResponse.id}`);
    }

    const authenticator = JSON.parse(fetched);
    console.log({ authenticator });

    const publicKey = decodeFirst<any>(
      Uint8Array.from(authenticator.credentialPublicKey)
    );
    const kty = publicKey.get(1);
    const alg = publicKey.get(3);
    const crv = publicKey.get(-1);
    const x = publicKey.get(-2);
    const y = publicKey.get(-3);
    const n = publicKey.get(-1);
    console.log({ x, y, crv, alg });

    const keyData = {
      kty: "EC",
      crv: "P-256",
      x: base64.fromArrayBuffer(x, true),
      y: base64.fromArrayBuffer(y, true),
      ext: false,
    };

    const parsedSignature = AsnParser.parse(signature, ECDSASigValue);
    let rBytes = new Uint8Array(parsedSignature.r);
    let sBytes = new Uint8Array(parsedSignature.s);

    if (shouldRemoveLeadingZero(rBytes)) {
      rBytes = rBytes.slice(1);
    }

    if (shouldRemoveLeadingZero(sBytes)) {
      sBytes = sBytes.slice(1);
    }

    // const finalSignature = isoUint8Array.concat([rBytes, sBytes]);
    const updatedSignature = concatUint8Arrays(rBytes, sBytes);

    const key = await window.crypto.subtle.importKey(
      "jwk",
      keyData,
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      false,
      ["verify"]
    );

    const result = await window.crypto.subtle.verify(
      { hash: { name: "SHA-256" }, name: "ECDSA" },
      key,
      updatedSignature,
      preimage
    );
    console.log({ result, updatedSignature });

    const response = await verifyAuthenticationResponse({
      response: authenticationResponse,
      expectedChallenge: "YXNkZg",
      expectedOrigin: window.location.origin,
      expectedRPID: window.location.hostname,
      authenticator: {
        credentialID: Uint8Array.from(authenticator.credentialID),
        credentialPublicKey: Uint8Array.from(authenticator.credentialPublicKey),
        counter: authenticator.counter,
      },
    });
    console.log({ response });
    // Inputs need to be little-endian
    setVerified(undefined);
    setLoading(true);
    const { data } = await axios.post(`${API_URL}/prove_evm`, {
      r: Array.from(new Uint8Array(rBytes)).reverse(),
      s: Array.from(new Uint8Array(sBytes)).reverse(),
      pubkey_x: Array.from(new Uint8Array(x)).reverse(),
      pubkey_y: Array.from(new Uint8Array(y)).reverse(),
      msghash: Array.from(new Uint8Array(hashedMessage)).reverse(),
      proving_key_path: "./keys/proving_key.pk",
    });
    console.log({ data });
    setLoading(false);
    setProof(data);
  }

  // FIXME
  async function sendToBundler() {
    console.log(1);
    const rpcUrl = "http://127.0.0.1:8545";
    console.log(2);
    const entryPoint = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
    console.log(3);
    const client = await Client.init(rpcUrl);
    console.log(4);
    const sender = "0xe0bff5a98bb11e3d7951bc10cf7c80e9a3d8b435";
    console.log(5);
    const builder = new UserOperationBuilder().useDefaults({
      sender,
      signature: proof,
    });
    console.log(6);
    const response = await client.sendUserOperation(builder);
    console.log(7);
    const userOperationEvent = await response.wait();
    // Userop with signature field = proof
  }

  async function createNewCredential() {
    const generatedRegistrationOptions = await generateRegistrationOptions({
      rpName: "demo",
      rpID: window.location.hostname,
      userID: username,
      userName: username,
      attestationType: "direct",
      challenge: "asdf",
      supportedAlgorithmIDs: [-7],
    });
    const startRegistrationResponse = await startRegistration(
      generatedRegistrationOptions
    );
    const verificationResponse = await verifyRegistrationResponse({
      response: startRegistrationResponse,
      expectedOrigin: window.location.origin,
      expectedChallenge: generatedRegistrationOptions.challenge,
      supportedAlgorithmIDs: [-7],
    });
    setResponse(verificationResponse);
    if (!verificationResponse.registrationInfo) {
      return;
    }
    const { id } = startRegistrationResponse;
    const { credentialID, credentialPublicKey, counter } =
      verificationResponse.registrationInfo;

    const publicKey = decodeFirst<any>(credentialPublicKey);
    const kty = publicKey.get(1);
    const alg = publicKey.get(3);
    const crv = publicKey.get(-1);
    const x = publicKey.get(-2);
    const y = publicKey.get(-3);
    const n = publicKey.get(-1);

    localStorage.setItem(
      id,
      JSON.stringify({
        credentialID: Array.from(credentialID),
        credentialPublicKey: Array.from(credentialPublicKey),
        counter,
      })
    );
  }

  return (
    <div className="w-screen h-screen flex justify-center items-center">
      <div className="flex flex-col items-center border-gray-200 border rounded-md p-8 gap-6">
        <Image width={80} height={80} src="/touchID.png" alt="Touch ID" />
        <h1 className="text-3xl font-bold text-orange-700">P-256 Wallet</h1>
        <p>Sign Ethereum transactions with only your fingerprint.</p>
        <input
          autoComplete="webauthn"
          className="rounded-md p-2"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <button
          className={`text-black font-bold py-2 px-4 rounded-md bg-white ${
            username ? "cursor-pointer hover:opacity-80" : ""
          }`}
          disabled={!username}
          onClick={createNewCredential}
        >
          Register new P-256 wallet
        </button>
        {!loading && (
          <button
            disabled={loading}
            className="cursor-pointer hover:opacity-80 text-white font-bold py-2 px-4 rounded bg-transparent border"
            onClick={loginCredential}
          >
            Sign transaction
          </button>
        )}
        {loading && (
          <div role="status">
            <svg
              aria-hidden="true"
              className="inline w-8 h-8 mr-2 text-gray-200 animate-spin dark:text-gray-600 fill-gray-600 dark:fill-gray-300"
              viewBox="0 0 100 101"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M100 50.5908C100 78.2051 77.6142 100.591 50 100.591C22.3858 100.591 0 78.2051 0 50.5908C0 22.9766 22.3858 0.59082 50 0.59082C77.6142 0.59082 100 22.9766 100 50.5908ZM9.08144 50.5908C9.08144 73.1895 27.4013 91.5094 50 91.5094C72.5987 91.5094 90.9186 73.1895 90.9186 50.5908C90.9186 27.9921 72.5987 9.67226 50 9.67226C27.4013 9.67226 9.08144 27.9921 9.08144 50.5908Z"
                fill="currentColor"
              />
              <path
                d="M93.9676 39.0409C96.393 38.4038 97.8624 35.9116 97.0079 33.5539C95.2932 28.8227 92.871 24.3692 89.8167 20.348C85.8452 15.1192 80.8826 10.7238 75.2124 7.41289C69.5422 4.10194 63.2754 1.94025 56.7698 1.05124C51.7666 0.367541 46.6976 0.446843 41.7345 1.27873C39.2613 1.69328 37.813 4.19778 38.4501 6.62326C39.0873 9.04874 41.5694 10.4717 44.0505 10.1071C47.8511 9.54855 51.7191 9.52689 55.5402 10.0491C60.8642 10.7766 65.9928 12.5457 70.6331 15.2552C75.2735 17.9648 79.3347 21.5619 82.5849 25.841C84.9175 28.9121 86.7997 32.2913 88.1811 35.8758C89.083 38.2158 91.5421 39.6781 93.9676 39.0409Z"
                fill="currentFill"
              />
            </svg>
            <span className="sr-only">Loading...</span>
          </div>
        )}
        {proof && (
          <div className="flex align-items gap-3">
            <div>
              The proof is: {proof.slice(0, 5)}...
              {proof.slice(proof.length - 5)}
            </div>

            <svg
              fill="none"
              stroke="currentColor"
              stroke-width="1.5"
              viewBox="0 0 24 24"
              xmlns="http://www.w3.org/2000/svg"
              aria-hidden="true"
              className="cursor-pointer hover:opacity-80 w-4"
              onClick={() => navigator.clipboard.writeText(proof)}
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184"
              ></path>
            </svg>
          </div>
        )}
        {proof && (
          <button
            disabled={verifyLoading}
            className={`${
              username ? "cursor-pointer hover:opacity-80" : ""
            } text-white font-bold py-2 px-4 rounded bg-transparent border`}
            onClick={async () => {
              setVerifyLoading(true);
              try {
                const { data } = await axios.post(`${API_URL}/verify_evm`, {
                  verifying_key_path: "verifying_key.vk",
                  proof,
                });
                if (data === "verified") {
                  setVerified(true);
                } else {
                  setVerified(false);
                }
              } catch {
                setVerified(false);
              }
              setVerifyLoading(false);
            }}
          >
            {(() => {
              if (verifyLoading) {
                return "Verifying...";
              }
              if (verified === false) {
                return "Invalid ❌";
              }
              if (verified === true) {
                return "Verified ✅";
              }
              return "Verify";
            })()}
          </button>
        )}
        {verified && (
          <button
            //  disabled={loading}
            className="cursor-pointer hover:opacity-80 text-white font-bold py-2 px-4 rounded bg-transparent border"
            onClick={sendToBundler}
          >
            Sign transaction
          </button>
        )}

        {response?.registrationInfo && (
          <>
            <div>Registered new credential</div>
            <div>aaguid: {response.registrationInfo.aaguid}</div>
            <div>
              credential device type:{" "}
              {response.registrationInfo.credentialDeviceType}
            </div>
            <div>
              credential id:{" "}
              {Buffer.from(response.registrationInfo.credentialID).toString(
                "base64"
              )}
            </div>
            <div>
              credential public key:{" "}
              {Buffer.from(
                response.registrationInfo.credentialPublicKey
              ).toString("base64")}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
