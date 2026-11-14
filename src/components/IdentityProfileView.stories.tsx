import type { Meta, StoryObj } from "@storybook/react";
import { SimulationError } from "stellar-id-client";
import type { IdentityPatch, ResolutionResult, Signer } from "stellar-id-client";
import { IdentityProfileView } from "./IdentityProfile.js";

const DID = "did:stellar:testnet:GDEMO000000000000000000000000000000000000000000000000";

const storySigner: Signer = {
  async publicKey() {
    return "GDEMO000000000000000000000000000000000000000000000000";
  },
  async signTransaction(xdr: string) {
    return xdr;
  },
};

function loaded(did = DID): ResolutionResult {
  return {
    did,
    didDocument: {
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
      id: did,
      verificationMethod: [
        {
          id: `${did}#key-1`,
          type: "Multikey",
          controller: did,
          publicKeyMultibase: "z6MkgAnvkP45uNxwCKeNdt6wrYkEjpYX4f7Nrd8MQqFL8Fbn",
        },
      ],
      authentication: [`${did}#key-1`],
      assertionMethod: [`${did}#key-1`],
      service: [
        { id: `${did}#demo`, type: "DemoService", serviceEndpoint: "https://example.com/demo" },
      ],
    },
    didResolutionMetadata: { contentType: "application/did+ld+json" },
    didDocumentMetadata: {
      created: 1792061782,
      updated: 1792063492,
      versionId: 2,
      method: { stellarAccount: "GDEMO" },
    },
  };
}

function createInteractiveHarness(did: string): {
  resolve: () => Promise<ResolutionResult>;
  update: (targetDid: string, patch: IdentityPatch) => Promise<{ hash: string }[]>;
} {
  let snapshot = loaded(did);
  return {
    resolve: async () => structuredClone(snapshot),
    update: async (_targetDid, patch) => {
      const doc = snapshot.didDocument;
      if (doc === null) {
        return [];
      }
      let verificationMethod = [...doc.verificationMethod];
      let service = [...doc.service];
      let authentication = [...doc.authentication];
      let assertionMethod = [...doc.assertionMethod];

      for (const key of patch.addKeys ?? []) {
        verificationMethod.push({
          id: `${did}#${key.id}`,
          type: "Multikey",
          controller: did,
          publicKeyMultibase: `z6Mk${key.publicKeyHex.slice(0, 40)}`,
        });
      }
      for (const svc of patch.addServices ?? []) {
        service.push({
          id: `${did}#${svc.id}`,
          type: svc.kind,
          serviceEndpoint: svc.endpoint,
        });
      }
      if (patch.authentication !== undefined) {
        authentication = patch.authentication.map((id) => `${did}#${id}`);
      }
      if (patch.assertionMethod !== undefined) {
        assertionMethod = patch.assertionMethod.map((id) => `${did}#${id}`);
      }
      if (patch.removeKeyIds !== undefined) {
        const drop = new Set(patch.removeKeyIds.map((id) => `${did}#${id}`));
        verificationMethod = verificationMethod.filter((vm) => !drop.has(vm.id));
      }
      if (patch.removeServiceIds !== undefined) {
        const drop = new Set(patch.removeServiceIds.map((id) => `${did}#${id}`));
        service = service.filter((svc) => !drop.has(svc.id));
      }

      snapshot = {
        ...snapshot,
        didDocument: {
          ...doc,
          verificationMethod,
          authentication,
          assertionMethod,
          service,
        },
      };
      return [{ hash: "deadbeef".repeat(8) }];
    },
  };
}

const meta: Meta<typeof IdentityProfileView> = {
  title: "Identity/IdentityProfile",
  component: IdentityProfileView,
};

export default meta;
type Story = StoryObj<typeof IdentityProfileView>;

/** Loaded read-only profile with one key and one service. */
export const Default: Story = {
  args: { did: DID, resolve: async () => loaded(DID) },
};

const editableDid = `${DID}EDIT`;
const interactive = createInteractiveHarness(editableDid);

/** Editable profile: add or remove keys and services in memory. */
export const Editable: Story = {
  args: {
    did: editableDid,
    signer: storySigner,
    resolve: interactive.resolve,
    update: interactive.update,
  },
};

/** Mutation pending state (update promise stays in flight on submit). */
export const EditingPending: Story = {
  args: {
    did: `${DID}PENDING`,
    signer: storySigner,
    resolve: async () => loaded(`${DID}PENDING`),
    update: () => new Promise(() => undefined as never),
  },
};

/** Mutation failure state (surfaces on-chain simulation rejection). */
export const EditingError: Story = {
  args: {
    did: `${DID}TXERR`,
    signer: storySigner,
    resolve: async () => loaded(`${DID}TXERR`),
    update: async () => {
      throw new SimulationError("Contract rejected mutation: InvalidVerificationMethod");
    },
  },
};

/** Loading state (resolver never settles). */
export const Loading: Story = {
  args: { did: `${DID}LOADING`, resolve: () => new Promise(() => undefined as never) },
};

/** Resolution failure. */
export const ErrorState: Story = {
  args: {
    did: `${DID}ERROR`,
    resolve: async () => {
      throw new Error("simulated RPC outage");
    },
  },
};

/** Deactivated DID tombstone (editing automatically disabled). */
export const Deactivated: Story = {
  args: {
    did: `${DID}DEACTIVATED`,
    signer: storySigner,
    resolve: async () => {
      const base = loaded(`${DID}DEACTIVATED`);
      return {
        ...base,
        didDocument:
          base.didDocument === null
            ? null
            : {
                ...base.didDocument,
                verificationMethod: [],
                authentication: [],
                assertionMethod: [],
                service: [],
              },
        didResolutionMetadata: { contentType: "application/did+ld+json", error: "deactivated" },
        didDocumentMetadata:
          base.didDocumentMetadata === null
            ? null
            : { ...base.didDocumentMetadata, deactivated: true },
      };
    },
  },
};

/** Dark theme with editing enabled. */
export const Dark: Story = {
  args: {
    did: `${DID}DARK`,
    signer: storySigner,
    resolve: async () => loaded(`${DID}DARK`),
    update: async () => [{ hash: "ab".repeat(32) }],
  },
  decorators: [
    (Story) => (
      <div data-sid-theme="dark" style={{ padding: 16, background: "var(--sid-color-background)" }}>
        <Story />
      </div>
    ),
  ],
};
