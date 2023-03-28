import { startRegistration } from "@simplewebauthn/browser";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  VerifiedRegistrationResponse,
} from "@simplewebauthn/server";
import { useState } from "react";
import styled from "styled-components";

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

export default function Home() {
  const [username, setUsername] = useState("");
  const [response, setResponse] = useState<VerifiedRegistrationResponse>();

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
    console.log({
      generatedRegistrationOptions,
      startRegistrationResponse,
      verificationResponse,
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
