import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { axe } from "jest-axe";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import {
  CredentialBadge,
  CredentialExpiredError,
  CredentialRevokedError,
  IdentityLogin,
  IdentityProfile,
  IdentityProfileView,
  InvalidProofError,
  SimulationError,
  withAuth,
} from "../src/index.js";
import type {
  IdentityPatch,
  ResolutionResult,
  VerifiableCredential,
} from "stellar-id-client";
import { fakeSigner, renderWithSession } from "./helpers.js";

vi.mock("stellar-id-client", async (importOriginal) => {
  const mod = await importOriginal<typeof import("stellar-id-client")>();
  return {
    ...mod,
    verifyChallengeResponse: vi.fn(async () => ({
      did: "did:stellar:testnet:GTESTADDRESS",
      address: "GTESTADDRESS",
    })),
  };
});

function credentialFixture(signatureHex = "ab".repeat(64)): VerifiableCredential {
  return {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    id: "http://example.edu/credentials/1",
    type: ["VerifiableCredential"],
    issuer: "did:stellar:testnet:GISSUER",
    issuanceDate: "2026-01-01T00:00:00.000Z",
    credentialSubject: { id: "did:stellar:testnet:GSUBJECT" },
    proof: {
      type: "StellarEd25519Proof",
      verificationMethod: "did:stellar:testnet:GISSUER#key-1",
      signatureHex,
    },
  };
}

function resolutionFixture(
  targetDid: string,
  opts?: {
    keyCount?: number;
    serviceCount?: number;
    deactivated?: boolean;
  },
): ResolutionResult {
  const keyCount = opts?.keyCount ?? 1;
  const serviceCount = opts?.serviceCount ?? 1;
  const deactivated = opts?.deactivated ?? false;
  const verificationMethod = deactivated
    ? []
    : Array.from({ length: keyCount }, (_, i) => ({
        id: `${targetDid}#key-${i + 1}`,
        type: "Multikey" as const,
        controller: targetDid,
        publicKeyMultibase: `z6MkKey${i + 1}`,
      }));
  const service = deactivated
    ? []
    : Array.from({ length: serviceCount }, (_, i) => ({
        id: `${targetDid}#svc-${i + 1}`,
        type: "Demo",
        serviceEndpoint: `https://example.com/${i + 1}`,
      }));

  return {
    did: targetDid,
    didDocument: {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: targetDid,
      verificationMethod,
      authentication: verificationMethod.length > 0 ? [`${targetDid}#key-1`] : [],
      assertionMethod: verificationMethod.length > 0 ? [`${targetDid}#key-1`] : [],
      service,
    },
    didResolutionMetadata: { contentType: "application/did+ld+json" },
    didDocumentMetadata: {
      created: 1,
      updated: 2,
      versionId: 1,
      deactivated,
      method: { stellarAccount: "GTESTADDRESS" },
    },
  };
}

describe("IdentityLogin", () => {
  it("signs in on click and announces the DID", async () => {
    const user = userEvent.setup();
    const seen: string[] = [];
    renderWithSession(<IdentityLogin onAuthenticated={(did) => seen.push(did)} />, () =>
      fakeSigner(),
    );
    await user.click(screen.getByRole("button", { name: /sign in with stellar/i }));
    expect(await screen.findByText(/did:stellar:testnet:GTESTADDRESS/)).toBeInTheDocument();
    expect(seen).toEqual(["did:stellar:testnet:GTESTADDRESS"]);
  });

  it("shows an alert on failure", async () => {
    const user = userEvent.setup();
    renderWithSession(<IdentityLogin />, () => ({
      ...fakeSigner(),
      async publicKey(): Promise<string> {
        throw new Error("locked");
      },
    }));
    await user.click(screen.getByRole("button", { name: /sign in with stellar/i }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });

  // TODO(wave: frontend-4): automated axe checks are the MVP; the written
  // WCAG audit with manual keyboard/screen-reader testing builds on them.
  it("has no axe violations", async () => {
    const { container } = renderWithSession(<IdentityLogin />, () => fakeSigner());
    expect(await axe(container)).toHaveNoViolations();
  });
});

describe("IdentityProfileView", () => {
  const did = "did:stellar:testnet:GTESTADDRESS";

  it("renders methods and services in read-only mode by default", async () => {
    render(
      <IdentityProfileView
        did={did}
        resolve={async () => ({
          did,
          didDocument: {
            "@context": ["https://www.w3.org/ns/did/v1"],
            id: did,
            verificationMethod: [
              {
                id: `${did}#key-1`,
                type: "Multikey",
                controller: did,
                publicKeyMultibase: "z6Mkabc",
              },
            ],
            authentication: [`${did}#key-1`],
            assertionMethod: [],
            service: [
              { id: `${did}#svc`, type: "Demo", serviceEndpoint: "https://example.com" },
            ],
          },
          didResolutionMetadata: { contentType: "application/did+ld+json" },
          didDocumentMetadata: {
            created: 1,
            updated: 2,
            versionId: 1,
            method: { stellarAccount: "GTESTADDRESS" },
          },
        })}
      />,
    );
    expect(await screen.findByText(`${did}#key-1`)).toBeInTheDocument();
    expect(screen.getByText("https://example.com")).toBeInTheDocument();
    expect(screen.queryByRole("form", { name: /add verification method/i })).not.toBeInTheDocument();
  });

  // NOTE: each case uses a distinct DID because useDidDocument caches by
  // DID; sharing one would leak resolved documents between cases.
  it("shows a loading state while resolving", () => {
    render(
      <IdentityProfileView
        did={`${did}-loading`}
        resolve={() => new Promise(() => undefined as never)}
      />,
    );
    expect(screen.getByText(/loading identity/i)).toBeInTheDocument();
  });

  it("reports resolution errors", async () => {
    render(
      <IdentityProfileView
        did={`${did}-broken`}
        resolve={async () => {
          throw new InvalidProofError("gone");
        }}
      />,
    );
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });

  it("has no axe violations on the loaded state", async () => {
    const { container } = render(
      <IdentityProfileView
        did={`${did}-empty-readonly`}
        resolve={async () => ({
          did: `${did}-empty-readonly`,
          didDocument: {
            "@context": ["https://www.w3.org/ns/did/v1"],
            id: `${did}-empty-readonly`,
            verificationMethod: [],
            authentication: [],
            assertionMethod: [],
            service: [],
          },
          didResolutionMetadata: { contentType: "application/did+ld+json" },
          didDocumentMetadata: {
            created: 1,
            updated: 1,
            versionId: 1,
            method: { stellarAccount: "GTESTADDRESS" },
          },
        })}
      />,
    );
    await screen.findByText("Identity");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("adds a verification method, announces progress/success, and refetches", async () => {
    const user = userEvent.setup();
    const targetDid = `${did}-add-key`;
    let snapshot = resolutionFixture(targetDid);
    let resolveCalls = 0;
    const resolve = vi.fn(async () => {
      resolveCalls += 1;
      return snapshot;
    });
    const update = vi.fn(async (_did: string, patch: IdentityPatch) => {
      const added = patch.addKeys?.[0];
      if (added !== undefined && snapshot.didDocument !== null) {
        snapshot = {
          ...snapshot,
          didDocument: {
            ...snapshot.didDocument,
            verificationMethod: [
              ...snapshot.didDocument.verificationMethod,
              {
                id: `${targetDid}#${added.id}`,
                type: "Multikey",
                controller: targetDid,
                publicKeyMultibase: "z6MkAdded",
              },
            ],
            authentication: (patch.authentication ?? []).map((id) => `${targetDid}#${id}`),
            assertionMethod: (patch.assertionMethod ?? []).map((id) => `${targetDid}#${id}`),
          },
        };
      }
      return [{ hash: "tx-add-key" }];
    });

    const signer = fakeSigner();
    render(
      <IdentityProfileView did={targetDid} signer={signer} resolve={resolve} update={update} />,
    );

    expect(await screen.findByText(`${targetDid}#key-1`)).toBeInTheDocument();
    expect(resolveCalls).toBe(1);

    const rawHex = "AB".repeat(32);
    await user.type(screen.getByLabelText(/^key id$/i), "key-2");
    await user.type(screen.getByLabelText(/public key/i), rawHex);
    await user.click(screen.getByRole("button", { name: /add verification method/i }));

    expect(await screen.findByText(`${targetDid}#key-2`)).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Added verification method #key-2.");
    expect(update).toHaveBeenCalledWith(
      targetDid,
      {
        addKeys: [{ id: "key-2", publicKeyHex: "ab".repeat(32) }],
        authentication: ["key-1", "key-2"],
        assertionMethod: ["key-1", "key-2"],
      },
      { signer },
    );
    expect(resolveCalls).toBe(2);
  });

  it("removes a referenced verification method only after confirmation and updates relationships", async () => {
    const user = userEvent.setup();
    const targetDid = `${did}-remove-key`;
    let snapshot = resolutionFixture(targetDid);
    const resolve = vi.fn(async () => snapshot);
    const update = vi.fn(async (_did: string, patch: IdentityPatch) => {
      if (snapshot.didDocument !== null && patch.removeKeyIds !== undefined) {
        snapshot = {
          ...snapshot,
          didDocument: {
            ...snapshot.didDocument,
            verificationMethod: [],
            authentication: [],
            assertionMethod: [],
          },
        };
      }
      return [{ hash: "tx-remove-key" }];
    });

    render(
      <IdentityProfileView
        did={targetDid}
        signer={fakeSigner()}
        resolve={resolve}
        update={update}
      />,
    );

    expect(await screen.findByText(`${targetDid}#key-1`)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Remove verification method key-1" }));

    // Cancelling confirmation leaves the key untouched and does not invoke update.
    const confirmGroup = screen.getByRole("group", {
      name: "Confirm removal of verification method key-1",
    });
    await user.click(within(confirmGroup).getByRole("button", { name: "Cancel" }));
    expect(update).not.toHaveBeenCalled();

    // Confirming triggers relationship cleanup + removal + refetch.
    await user.click(screen.getByRole("button", { name: "Remove verification method key-1" }));
    await user.click(screen.getByRole("button", { name: "Confirm remove" }));

    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update).toHaveBeenCalledWith(
      targetDid,
      {
        authentication: [],
        assertionMethod: [],
        removeKeyIds: ["key-1"],
      },
      expect.objectContaining({ signer: expect.any(Object) }),
    );
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Removed verification method #key-1.",
    );
    expect(screen.queryByText(`${targetDid}#key-1`)).not.toBeInTheDocument();
  });

  it("adds and removes a service endpoint with confirmation and refetch", async () => {
    const user = userEvent.setup();
    const targetDid = `${did}-services`;
    let snapshot = resolutionFixture(targetDid, { serviceCount: 0 });
    const resolve = vi.fn(async () => snapshot);
    const update = vi.fn(async (_did: string, patch: IdentityPatch) => {
      if (snapshot.didDocument !== null) {
        let nextServices = [...snapshot.didDocument.service];
        for (const svc of patch.addServices ?? []) {
          nextServices.push({
            id: `${targetDid}#${svc.id}`,
            type: svc.kind,
            serviceEndpoint: svc.endpoint,
          });
        }
        for (const id of patch.removeServiceIds ?? []) {
          nextServices = nextServices.filter((s) => s.id !== `${targetDid}#${id}`);
        }
        snapshot = {
          ...snapshot,
          didDocument: { ...snapshot.didDocument, service: nextServices },
        };
      }
      return [{ hash: "tx-service" }];
    });

    render(
      <IdentityProfileView
        did={targetDid}
        signer={fakeSigner()}
        resolve={resolve}
        update={update}
      />,
    );

    await screen.findByText("Identity");

    await user.type(screen.getByLabelText(/^service id$/i), "issuer");
    await user.type(screen.getByLabelText(/^service type$/i), "CredentialIssuer");
    await user.type(screen.getByLabelText(/service endpoint/i), "https://issuer.example.org/vc");
    await user.click(screen.getByRole("button", { name: /^add service$/i }));

    expect(await screen.findByText("https://issuer.example.org/vc")).toBeInTheDocument();
    expect(update).toHaveBeenLastCalledWith(
      targetDid,
      {
        addServices: [
          { id: "issuer", kind: "CredentialIssuer", endpoint: "https://issuer.example.org/vc" },
        ],
      },
      expect.objectContaining({ signer: expect.any(Object) }),
    );

    await user.click(screen.getByRole("button", { name: "Remove service issuer" }));
    await user.click(screen.getByRole("button", { name: "Confirm remove" }));

    await waitFor(() =>
      expect(screen.queryByText("https://issuer.example.org/vc")).not.toBeInTheDocument(),
    );
    expect(screen.getByRole("status")).toHaveTextContent("Removed service #issuer.");
  });

  it("enforces contract limits and input validation before calling update", async () => {
    const user = userEvent.setup();
    const targetDid = `${did}-validation`;
    const update = vi.fn(async () => [{ hash: "never" }]);

    render(
      <IdentityProfileView
        did={targetDid}
        signer={fakeSigner()}
        resolve={async () => resolutionFixture(targetDid)}
        update={update}
      />,
    );

    await screen.findByText(`${targetDid}#key-1`);

    // Duplicate key ID
    await user.type(screen.getByLabelText(/^key id$/i), "key-1");
    await user.type(screen.getByLabelText(/public key/i), "11".repeat(32));
    await user.click(screen.getByRole("button", { name: /add verification method/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/already exists/i);

    // Multi-byte UTF-8 fragment ID exceeding 128 bytes (45 * 3-byte chars = 135 UTF-8 bytes)
    fireEvent.change(screen.getByLabelText(/^key id$/i), {
      target: { value: "€".repeat(45) },
    });
    await user.click(screen.getByRole("button", { name: /add verification method/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/128 UTF-8 bytes/i);

    // Invalid Ed25519 hex public key
    fireEvent.change(screen.getByLabelText(/^key id$/i), { target: { value: "key-valid" } });
    fireEvent.change(screen.getByLabelText(/public key/i), { target: { value: "not-valid-hex" } });
    await user.click(screen.getByRole("button", { name: /add verification method/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/64 hexadecimal characters/i);

    // Non-https service endpoint
    await user.type(screen.getByLabelText(/^service id$/i), "plain-http");
    await user.type(screen.getByLabelText(/^service type$/i), "Demo");
    fireEvent.change(screen.getByLabelText(/service endpoint/i), {
      target: { value: "http://insecure.example.com" },
    });
    await user.click(screen.getByRole("button", { name: /^add service$/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/https:\/\//i);

    // Endpoint > 512 UTF-8 bytes
    fireEvent.change(screen.getByLabelText(/service endpoint/i), {
      target: { value: `https://example.com/${"a".repeat(505)}` },
    });
    await user.click(screen.getByRole("button", { name: /^add service$/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/512 UTF-8 bytes/i);

    expect(update).not.toHaveBeenCalled();
  });

  it("blocks adding an 11th key or 11th service at the 10-entry contract cap", async () => {
    const user = userEvent.setup();
    const targetDid = `${did}-limits`;
    const update = vi.fn(async () => [{ hash: "never" }]);

    render(
      <IdentityProfileView
        did={targetDid}
        signer={fakeSigner()}
        resolve={async () => resolutionFixture(targetDid, { keyCount: 10, serviceCount: 10 })}
        update={update}
      />,
    );

    await screen.findByText(`${targetDid}#key-10`);

    await user.type(screen.getByLabelText(/^key id$/i), "key-11");
    await user.type(screen.getByLabelText(/public key/i), "22".repeat(32));
    await user.click(screen.getByRole("button", { name: /add verification method/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /maximum of 10 verification methods/i,
    );

    await user.type(screen.getByLabelText(/^service id$/i), "svc-11");
    await user.type(screen.getByLabelText(/^service type$/i), "Demo");
    await user.type(screen.getByLabelText(/service endpoint/i), "https://example.com/11");
    await user.click(screen.getByRole("button", { name: /^add service$/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/maximum of 10 services/i);

    expect(update).not.toHaveBeenCalled();
  });

  it("announces pending and failure states and preserves form values on mutation error", async () => {
    const user = userEvent.setup();
    const targetDid = `${did}-tx-failure`;
    let rejectUpdate!: (reason: Error) => void;
    const update = vi.fn(
      () =>
        new Promise<{ hash: string }[]>((_resolve, reject) => {
          rejectUpdate = reject;
        }),
    );

    render(
      <IdentityProfileView
        did={targetDid}
        signer={fakeSigner()}
        resolve={async () => resolutionFixture(targetDid)}
        update={update}
      />,
    );

    await screen.findByText(`${targetDid}#key-1`);

    await user.type(screen.getByLabelText(/^service id$/i), "broken-svc");
    await user.type(screen.getByLabelText(/^service type$/i), "LinkedDomains");
    await user.type(screen.getByLabelText(/service endpoint/i), "https://broken.example.com");
    await user.click(screen.getByRole("button", { name: /^add service$/i }));

    expect(screen.getByRole("status")).toHaveTextContent("Adding service #broken-svc…");
    expect(screen.getByRole("button", { name: /^add service$/i })).toBeDisabled();

    await act(async () => {
      rejectUpdate(new SimulationError("ContractError(LimitExceeded)"));
    });

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /Could not add service #broken-svc:.*ContractError\(LimitExceeded\)/,
    );
    expect(screen.getByLabelText(/^service id$/i)).toHaveValue("broken-svc");
  });

  it("supports keyboard-only confirmation dismissal (Escape restores focus) and submission", async () => {
    const user = userEvent.setup();
    const targetDid = `${did}-keyboard`;
    const update = vi.fn(async () => [{ hash: "tx-kb" }]);

    render(
      <IdentityProfileView
        did={targetDid}
        signer={fakeSigner()}
        resolve={async () => resolutionFixture(targetDid)}
        update={update}
      />,
    );

    const removeBtn = await screen.findByRole("button", {
      name: "Remove verification method key-1",
    });
    removeBtn.focus();
    await user.keyboard("{Enter}");

    // Focus moves to Cancel inside the confirmation group; Escape dismisses and restores focus.
    expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus();
    await user.keyboard("{Escape}");
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Remove verification method key-1" }),
      ).toHaveFocus(),
    );
    expect(update).not.toHaveBeenCalled();

    // Submit service form with Enter key
    const svcIdInput = screen.getByLabelText(/^service id$/i);
    svcIdInput.focus();
    await user.keyboard("kb-svc{Tab}LinkedDomains{Tab}https://kb.example.com{Tab}{Enter}");
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
  });

  it("disables editing on a deactivated DID even when a signer is provided", async () => {
    const targetDid = `${did}-deactivated-signer`;
    render(
      <IdentityProfileView
        did={targetDid}
        signer={fakeSigner()}
        resolve={async () => resolutionFixture(targetDid, { deactivated: true })}
      />,
    );

    expect(await screen.findByText("Deactivated")).toBeInTheDocument();
    expect(screen.getByText(/deactivated and cannot be modified/i)).toBeInTheDocument();
    expect(screen.queryByRole("form", { name: /add verification method/i })).not.toBeInTheDocument();
  });

  it("wires the authenticated session signer automatically in IdentityProfile", async () => {
    const user = userEvent.setup();
    const sessionDid = "did:stellar:testnet:GTESTADDRESS";
    const update = vi.fn(async () => [{ hash: "tx-session" }]);

    renderWithSession(
      <>
        <IdentityLogin />
        <IdentityProfile
          resolve={async () => resolutionFixture(sessionDid)}
          update={update}
        />
      </>,
      () => fakeSigner(),
    );

    await user.click(screen.getByRole("button", { name: /sign in with stellar/i }));
    expect(
      await screen.findByRole("form", { name: /add verification method/i }),
    ).toBeInTheDocument();
  });

  it("has no axe violations across editable, confirmation, and error states", async () => {
    const user = userEvent.setup();
    const targetDid = `${did}-axe-editable`;
    const { container } = render(
      <div data-sid-theme="light">
        <IdentityProfileView
          did={targetDid}
          signer={fakeSigner()}
          resolve={async () => resolutionFixture(targetDid)}
          update={async () => [{ hash: "ok" }]}
        />
      </div>,
    );

    await screen.findByText(`${targetDid}#key-1`);
    expect(await axe(container)).toHaveNoViolations();

    // Open destructive confirmation and trigger validation error, then re-run axe.
    await user.click(screen.getByRole("button", { name: "Remove verification method key-1" }));
    await user.click(screen.getByRole("button", { name: /^add service$/i }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });
});

describe("CredentialBadge", () => {
  // NOTE: each case uses a distinct signatureHex because useCredential
  // caches by signature; sharing one fixture would leak state between cases.
  it.each([
    ["valid", "aa", async () => ({ valid: true as const, did: "d", hash: "h" }), "Valid credential"],
    ["revoked", "bb", async () => { throw new CredentialRevokedError("ab"); }, "Revoked credential"],
    ["expired", "cc", async () => { throw new CredentialExpiredError("ab"); }, "Expired credential"],
    ["unknown", "dd", async () => { throw new InvalidProofError("x"); }, "Unknown credential"],
  ])("shows %s", async (_name, sig, verify, label) => {
    render(<CredentialBadge credential={credentialFixture(sig.repeat(64))} verify={verify} />);
    expect(await screen.findByText(label)).toBeInTheDocument();
  });

  it("renders idle without a credential", () => {
    render(<CredentialBadge credential={null} />);
    expect(screen.getByText("No credential")).toBeInTheDocument();
  });

  it("revalidates when refreshToken changes", async () => {
    let calls = 0;
    const verify = async () => {
      calls += 1;
      return { valid: true as const, did: "d", hash: "h" };
    };
    const { rerender } = render(
      <CredentialBadge credential={credentialFixture("ee".repeat(64))} verify={verify} />,
    );
    expect(await screen.findByText("Valid credential")).toBeInTheDocument();
    expect(calls).toBe(1);
    rerender(
      <CredentialBadge
        credential={credentialFixture("ee".repeat(64))}
        verify={verify}
        refreshToken={1}
      />,
    );
    await waitFor(() => expect(calls).toBe(2));
    expect(await screen.findByText("Valid credential")).toBeInTheDocument();
  });

  it("has no axe violations", async () => {
    const { container } = render(
      <CredentialBadge
        credential={credentialFixture()}
        verify={async () => ({ valid: true as const, did: "d", hash: "h" })}
      />,
    );
    await screen.findByText("Valid credential");
    expect(await axe(container)).toHaveNoViolations();
  });
});

describe("withAuth", () => {
  function Secret() {
    return <p>classified</p>;
  }

  it("gates content behind authentication", async () => {
    const user = userEvent.setup();
    const Guarded = withAuth(Secret);
    renderWithSession(
      <>
        <IdentityLogin />
        <Guarded />
      </>,
      () => fakeSigner(),
    );
    expect(screen.getByText(/sign in to continue/i)).toBeInTheDocument();
    await act(async () => {
      await user.click(screen.getByRole("button", { name: /sign in with stellar/i }));
    });
    expect(await screen.findByText("classified")).toBeInTheDocument();
  });

  it("supports a custom fallback", () => {
    const Guarded = withAuth(Secret, { fallback: <p>locked out</p> });
    renderWithSession(<Guarded />, () => fakeSigner());
    expect(screen.getByText("locked out")).toBeInTheDocument();
  });
});
