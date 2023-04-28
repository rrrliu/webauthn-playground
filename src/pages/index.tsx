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
import styled from "styled-components";
import { AsnParser } from "@peculiar/asn1-schema";
import { ECDSASigValue } from "@peculiar/asn1-ecc";
import axios from "axios";

const Container = styled.div`
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 24px;
`;

const Heading = styled.div`
  font-size: 36;
`;

const Subheading = styled.div`
  font-size: 36;
`;

const InputField = styled.input``;

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

interface Authenticator {
  credentialID: Uint8Array;
  credentialPublicKey: Uint8Array;
  counter: number;
}

export default function Home() {
  const [username, setUsername] = useState("");
  const [response, setResponse] = useState<VerifiedRegistrationResponse>();
  const [proof, setProof] = useState("");
  const [loading, setLoading] = useState(false);

  async function loginCredential() {
    const authenticationOptions = await generateAuthenticationOptions({
      rpID: window.location.hostname,
      challenge: "asdf",
    });
    const authenticationResponse = await startAuthentication(
      authenticationOptions
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

    // const parsedSignature = AsnParser.parse(signature);
    // let rBytes = new Uint8Array(parsedSignature.r);
    // let sBytes = new Uint8Array(parsedSignature.s);

    // if (shouldRemoveLeadingZero(rBytes)) {
    //   rBytes = rBytes.slice(1);
    // }

    // if (shouldRemoveLeadingZero(sBytes)) {
    //   sBytes = sBytes.slice(1);
    // }

    // const updatedSignature = concatUint8Arrays(rBytes, sBytes);
    // const jose = derToJose(authenticationResponse.response.signature, "ES256");

    // const updatedSignature = base64.toArrayBuffer(jose, false);
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
      expectedOrigin: [
        "http://localhost:3000",
        "https://webauthn-playground-rrrliu.vercel.app",
        "https://webauthn-playground.vercel.app",
      ],
      expectedRPID: window.location.hostname,
      authenticator: {
        credentialID: Uint8Array.from(authenticator.credentialID),
        credentialPublicKey: Uint8Array.from(authenticator.credentialPublicKey),
        counter: authenticator.counter,
      },
    });
    console.log({ response });
    // Inputs need to be little-endian
    const { data } = await axios.post("http://localhost:8000/prove", {
      r: Array.from(new Uint8Array(rBytes)).reverse(),
      s: Array.from(new Uint8Array(sBytes)).reverse(),
      pubkey_x: Array.from(new Uint8Array(x)).reverse(),
      pubkey_y: Array.from(new Uint8Array(y)).reverse(),
      msghash: Array.from(new Uint8Array(hashedMessage)).reverse(),
      proving_key_path: "./proving_key.pk",
    });
    console.log({ data });
    setProof(data);
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
      expectedOrigin: [
        "http://localhost:3000",
        "https://webauthn-playground-rrrliu.vercel.app",
        "https://webauthn-playground.vercel.app",
      ],
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

    console.log({
      publicKey,
      generatedRegistrationOptions,
      startRegistrationResponse,
      verificationResponse,
      kty,
      alg,
      crv,
      x,
      y,
      n,
    });
  }

  return (
    <Container>
      <Heading>WebAuthn testing</Heading>
      <InputField
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <button disabled={!username} onClick={createNewCredential}>
        Register
      </button>
      <button onClick={loginCredential}>Authenticate</button>
      {loading && <div>Waiting for the proof to generate...</div>}
      {proof && <div>The proof is: {proof}</div>}
      {response?.registrationInfo && (
        <>
          <Subheading>Registered new credential</Subheading>
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
    </Container>
  );
}
