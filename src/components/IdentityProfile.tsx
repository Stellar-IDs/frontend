"use client";

/**
 * Identity profile: DID document inspection plus optional key and service
 * management backed by `updateIdentity` from `stellar-id-client`.
 */
import { useEffect, useId, useRef, useState } from "react";
import type { FormEvent, KeyboardEvent } from "react";
import { updateIdentity } from "stellar-id-client";
import type {
  IdentityPatch,
  MutateOptions,
  NetworkConfig,
  ResolutionResult,
  Signer,
  TxResult,
} from "stellar-id-client";
import { useDidDocument } from "../hooks/useStellarQueries.js";
import { useIdentity, useSessionSigner } from "../session/SessionProvider.js";
import "./IdentityProfile.css";

/** Contract limit: maximum verification methods per DID in `stellar-id-core`. */
export const MAX_VERIFICATION_METHODS = 10;

/** Contract limit: maximum service endpoints per DID in `stellar-id-core`. */
export const MAX_SERVICES = 10;

/** Contract limit: maximum UTF-8 byte length for key and service fragment IDs. */
export const MAX_FRAGMENT_ID_BYTES = 128;

/** Contract limit: maximum UTF-8 byte length for service `kind` values. */
export const MAX_SERVICE_KIND_BYTES = 128;

/** Contract limit: maximum UTF-8 byte length for `https://` service endpoints. */
export const MAX_SERVICE_ENDPOINT_BYTES = 512;

const ED25519_HEX_PATTERN = /^[0-9a-fA-F]{64}$/;

/** Injectable updater signature matching `updateIdentity` from `stellar-id-client`. */
export type UpdateIdentityFn = (
  did: string,
  patch: IdentityPatch,
  opts: MutateOptions,
) => Promise<TxResult[]>;

/** Props for {@link IdentityProfile} and {@link IdentityProfileView}. */
export interface IdentityProfileProps {
  /** DID to show (`IdentityProfile` defaults to the session DID). */
  did?: string;
  /** Network (defaults to testnet). */
  network?: NetworkConfig;
  /** Injected resolver for tests and stories. */
  resolve?: (did: string, opts?: { network?: NetworkConfig }) => Promise<ResolutionResult>;
  /**
   * Authorizing signer for mutations (`IdentityProfile` defaults to the
   * authenticated session signer when viewing the session DID).
   */
  signer?: Signer | null;
  /**
   * Enable or disable editing controls. Defaults to `true` when a `signer`
   * is provided and the DID is active.
   */
  editable?: boolean;
  /** Injected `updateIdentity` implementation for tests and stories. */
  update?: UpdateIdentityFn;
  /** Called after an on-chain update succeeds. */
  onUpdated?: (results: TxResult[], patch: IdentityPatch) => void;
}

type MutationState =
  | { status: "idle" }
  | { status: "pending"; message: string }
  | { status: "success"; message: string }
  | { status: "error"; message: string };

interface PendingRemoval {
  kind: "key" | "service";
  fragmentId: string;
}

function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

/**
 * Strip the `<did>#` prefix from a W3C-qualified identifier when present.
 *
 * @param identifier - Qualified (`did:stellar:...#key-1`) or bare fragment (`key-1`).
 * @param did - Owning DID string.
 * @returns The bare fragment identifier.
 */
export function extractFragmentId(identifier: string, did: string): string {
  const prefix = `${did}#`;
  if (identifier.startsWith(prefix)) {
    return identifier.slice(prefix.length);
  }
  const hashIndex = identifier.indexOf("#");
  return hashIndex >= 0 ? identifier.slice(hashIndex + 1) : identifier;
}

function validateFragmentId(
  rawId: string,
  existingFragments: readonly string[],
  label: "Key ID" | "Service ID",
): string | null {
  const trimmed = rawId.trim();
  if (trimmed.length === 0) {
    return `${label} is required.`;
  }
  if (trimmed.includes("#") || /\s/.test(trimmed)) {
    return `${label} must be a fragment identifier without '#' or whitespace.`;
  }
  if (utf8ByteLength(trimmed) > MAX_FRAGMENT_ID_BYTES) {
    return `${label} must be ${MAX_FRAGMENT_ID_BYTES} UTF-8 bytes or fewer.`;
  }
  if (existingFragments.includes(trimmed)) {
    return `${label} "${trimmed}" already exists on this identity.`;
  }
  return null;
}

/**
 * Validate a candidate verification method against `stellar-id-core` limits.
 *
 * @param rawId - Candidate fragment ID.
 * @param rawPublicKeyHex - Candidate 32-byte Ed25519 hex public key.
 * @param existingKeyFragments - Existing verification method fragment IDs.
 * @returns Validation error message, or `null` when valid.
 */
export function validateNewKey(
  rawId: string,
  rawPublicKeyHex: string,
  existingKeyFragments: readonly string[],
): string | null {
  if (existingKeyFragments.length >= MAX_VERIFICATION_METHODS) {
    return `Maximum of ${MAX_VERIFICATION_METHODS} verification methods reached. Remove a key before adding another.`;
  }
  const idError = validateFragmentId(rawId, existingKeyFragments, "Key ID");
  if (idError !== null) {
    return idError;
  }
  const hex = rawPublicKeyHex.trim();
  if (hex.length === 0) {
    return "Public key hex is required.";
  }
  if (!ED25519_HEX_PATTERN.test(hex)) {
    return "Public key must be 64 hexadecimal characters (32-byte Ed25519 key).";
  }
  return null;
}

/**
 * Validate a candidate service endpoint against `stellar-id-core` limits.
 *
 * @param rawId - Candidate fragment ID.
 * @param rawKind - Candidate service type/kind.
 * @param rawEndpoint - Candidate `https://` URL.
 * @param existingServiceFragments - Existing service fragment IDs.
 * @returns Validation error message, or `null` when valid.
 */
export function validateNewService(
  rawId: string,
  rawKind: string,
  rawEndpoint: string,
  existingServiceFragments: readonly string[],
): string | null {
  if (existingServiceFragments.length >= MAX_SERVICES) {
    return `Maximum of ${MAX_SERVICES} services reached. Remove a service before adding another.`;
  }
  const idError = validateFragmentId(rawId, existingServiceFragments, "Service ID");
  if (idError !== null) {
    return idError;
  }
  const kind = rawKind.trim();
  if (kind.length === 0) {
    return "Service type is required.";
  }
  if (utf8ByteLength(kind) > MAX_SERVICE_KIND_BYTES) {
    return `Service type must be ${MAX_SERVICE_KIND_BYTES} UTF-8 bytes or fewer.`;
  }
  const endpoint = rawEndpoint.trim();
  if (endpoint.length === 0) {
    return "Service endpoint URL is required.";
  }
  if (!endpoint.startsWith("https://")) {
    return "Service endpoint must start with https://.";
  }
  try {
    const parsed = new URL(endpoint);
    if (parsed.protocol !== "https:" || parsed.hostname.length === 0) {
      return "Service endpoint must be a valid https:// URL.";
    }
  } catch {
    return "Service endpoint must be a valid https:// URL.";
  }
  if (utf8ByteLength(endpoint) > MAX_SERVICE_ENDPOINT_BYTES) {
    return `Service endpoint must be ${MAX_SERVICE_ENDPOINT_BYTES} UTF-8 bytes or fewer.`;
  }
  return null;
}

/**
 * Display a DID document: methods, relationships, and services, with optional
 * key and service editing when a controller `signer` is supplied.
 *
 * Session-independent view: pass the DID (and optional `signer`/`update`)
 * explicitly. No provider needed, which keeps tests and stories hermetic.
 *
 * @param props - DID, network, and optional injected resolver/signer/updater.
 */
export function IdentityProfileView({
  did,
  network,
  resolve,
  signer = null,
  editable,
  update = updateIdentity,
  onUpdated,
}: {
  did: string | null;
} & Omit<IdentityProfileProps, "did">): React.JSX.Element {
  const uid = useId();
  const { data, error, status, refetch } = useDidDocument(did, { network, resolve });

  // Retain the last resolved document for the current DID so post-mutation
  // refetches update in place without unmounting forms or dropping focus.
  const lastResolvedRef = useRef<{ did: string; result: ResolutionResult } | null>(null);
  if (did !== null && data !== null) {
    lastResolvedRef.current = { did, result: data };
  } else if (did === null || (lastResolvedRef.current !== null && lastResolvedRef.current.did !== did)) {
    lastResolvedRef.current = null;
  }

  const [keyId, setKeyId] = useState("");
  const [publicKeyHex, setPublicKeyHex] = useState("");
  const [includeAuthentication, setIncludeAuthentication] = useState(true);
  const [includeAssertionMethod, setIncludeAssertionMethod] = useState(true);

  const [serviceId, setServiceId] = useState("");
  const [serviceKind, setServiceKind] = useState("");
  const [serviceEndpoint, setServiceEndpoint] = useState("");

  const [mutation, setMutation] = useState<MutationState>({ status: "idle" });
  const [confirming, setConfirming] = useState<PendingRemoval | null>(null);

  const cancelButtonRef = useRef<HTMLButtonElement | null>(null);
  const removeButtonRefs = useRef<Map<string, HTMLButtonElement>>(new Map());
  const restoreFocusKeyRef = useRef<string | null>(null);

  useEffect(() => {
    setKeyId("");
    setPublicKeyHex("");
    setIncludeAuthentication(true);
    setIncludeAssertionMethod(true);
    setServiceId("");
    setServiceKind("");
    setServiceEndpoint("");
    setMutation({ status: "idle" });
    setConfirming(null);
  }, [did]);

  useEffect(() => {
    if (confirming !== null) {
      cancelButtonRef.current?.focus();
    } else if (restoreFocusKeyRef.current !== null) {
      const target = removeButtonRefs.current.get(restoreFocusKeyRef.current);
      restoreFocusKeyRef.current = null;
      target?.focus();
    }
  }, [confirming]);

  if (did === null) {
    return (
      <section className="sid-profile" aria-label="Identity profile">
        <p className="sid-profile__empty">No identity selected. Sign in to view a profile.</p>
      </section>
    );
  }

  const resolvedData =
    data ?? (lastResolvedRef.current?.did === did ? lastResolvedRef.current.result : null);

  if ((status === "loading" || status === "idle") && resolvedData === null) {
    return (
      <section className="sid-profile" aria-label="Identity profile">
        <p role="status">Loading identity…</p>
      </section>
    );
  }

  if (status === "error" && resolvedData === null) {
    return (
      <section className="sid-profile" aria-label="Identity profile">
        <p role="alert" className="sid-profile__error">
          Could not load {did}: {error?.message ?? "unknown error"}
        </p>
      </section>
    );
  }

  if (resolvedData === null) {
    return (
      <section className="sid-profile" aria-label="Identity profile">
        <p role="alert" className="sid-profile__error">
          Could not load {did}: {error?.message ?? "unknown error"}
        </p>
      </section>
    );
  }

  const document = resolvedData.didDocument;
  if (document === null) {
    return (
      <section className="sid-profile" aria-label="Identity profile">
        <p role="status">No document found for {did}.</p>
      </section>
    );
  }

  const deactivated = resolvedData.didDocumentMetadata?.deactivated === true;
  const wantsEdit = editable ?? signer !== null;
  const canEdit = wantsEdit && signer !== null && !deactivated;
  const isMutating = mutation.status === "pending";

  const existingKeyFragments = document.verificationMethod.map((vm) =>
    extractFragmentId(vm.id, document.id),
  );
  const existingServiceFragments = document.service.map((svc) =>
    extractFragmentId(svc.id, document.id),
  );
  const existingAuthFragments = document.authentication.map((ref) =>
    extractFragmentId(ref, document.id),
  );
  const existingAssertionFragments = document.assertionMethod.map((ref) =>
    extractFragmentId(ref, document.id),
  );

  const authSet = new Set(existingAuthFragments);
  const assertionSet = new Set(existingAssertionFragments);

  const registerRemoveRef =
    (refKey: string) =>
    (element: HTMLButtonElement | null): void => {
      if (element === null) {
        removeButtonRefs.current.delete(refKey);
      } else {
        removeButtonRefs.current.set(refKey, element);
      }
    };

  const requestRemove = (kind: "key" | "service", fragmentId: string): void => {
    if (isMutating) {
      return;
    }
    setConfirming({ kind, fragmentId });
  };

  const cancelConfirmation = (): void => {
    if (confirming !== null) {
      restoreFocusKeyRef.current = `${confirming.kind}:${confirming.fragmentId}`;
    }
    setConfirming(null);
  };

  const handleConfirmationKeyDown = (event: KeyboardEvent<HTMLDivElement>): void => {
    if (event.key === "Escape" && !isMutating) {
      event.preventDefault();
      cancelConfirmation();
    }
  };

  const runPatch = async (
    patch: IdentityPatch,
    pendingMessage: string,
    successMessage: string,
    failurePrefix: string,
    onSuccessReset?: () => void,
  ): Promise<void> => {
    if (signer === null) {
      return;
    }
    setMutation({ status: "pending", message: pendingMessage });
    try {
      const results = await update(
        document.id,
        patch,
        network !== undefined ? { signer, network } : { signer },
      );
      onSuccessReset?.();
      setMutation({ status: "success", message: successMessage });
      refetch();
      onUpdated?.(results, patch);
    } catch (err) {
      const detail = err instanceof Error ? err.message : "Transaction failed.";
      setMutation({ status: "error", message: `${failurePrefix}: ${detail}` });
    }
  };

  const handleAddKey = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    if (signer === null || isMutating) {
      return;
    }
    const validationError = validateNewKey(keyId, publicKeyHex, existingKeyFragments);
    if (validationError !== null) {
      setMutation({ status: "error", message: validationError });
      return;
    }
    const normalizedId = keyId.trim();
    const normalizedHex = publicKeyHex.trim().toLowerCase();
    const patch: IdentityPatch = {
      addKeys: [{ id: normalizedId, publicKeyHex: normalizedHex }],
      ...(includeAuthentication || includeAssertionMethod
        ? {
            authentication: includeAuthentication
              ? [...existingAuthFragments, normalizedId]
              : existingAuthFragments,
            assertionMethod: includeAssertionMethod
              ? [...existingAssertionFragments, normalizedId]
              : existingAssertionFragments,
          }
        : {}),
    };
    await runPatch(
      patch,
      `Adding verification method #${normalizedId}…`,
      `Added verification method #${normalizedId}.`,
      `Could not add verification method #${normalizedId}`,
      () => {
        setKeyId("");
        setPublicKeyHex("");
        setIncludeAuthentication(true);
        setIncludeAssertionMethod(true);
      },
    );
  };

  const handleAddService = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    if (signer === null || isMutating) {
      return;
    }
    const validationError = validateNewService(
      serviceId,
      serviceKind,
      serviceEndpoint,
      existingServiceFragments,
    );
    if (validationError !== null) {
      setMutation({ status: "error", message: validationError });
      return;
    }
    const normalizedId = serviceId.trim();
    const normalizedKind = serviceKind.trim();
    const normalizedEndpoint = serviceEndpoint.trim();
    const patch: IdentityPatch = {
      addServices: [{ id: normalizedId, kind: normalizedKind, endpoint: normalizedEndpoint }],
    };
    await runPatch(
      patch,
      `Adding service #${normalizedId}…`,
      `Added service #${normalizedId}.`,
      `Could not add service #${normalizedId}`,
      () => {
        setServiceId("");
        setServiceKind("");
        setServiceEndpoint("");
      },
    );
  };

  const handleConfirmRemove = async (): Promise<void> => {
    if (confirming === null || signer === null || isMutating) {
      return;
    }
    const { kind, fragmentId } = confirming;
    if (kind === "key") {
      const wasReferenced = authSet.has(fragmentId) || assertionSet.has(fragmentId);
      const patch: IdentityPatch = {
        ...(wasReferenced
          ? {
              authentication: existingAuthFragments.filter((id) => id !== fragmentId),
              assertionMethod: existingAssertionFragments.filter((id) => id !== fragmentId),
            }
          : {}),
        removeKeyIds: [fragmentId],
      };
      await runPatch(
        patch,
        `Removing verification method #${fragmentId}…`,
        `Removed verification method #${fragmentId}.`,
        `Could not remove verification method #${fragmentId}`,
        () => {
          setConfirming(null);
        },
      );
      return;
    }

    const patch: IdentityPatch = {
      removeServiceIds: [fragmentId],
    };
    await runPatch(
      patch,
      `Removing service #${fragmentId}…`,
      `Removed service #${fragmentId}.`,
      `Could not remove service #${fragmentId}`,
      () => {
        setConfirming(null);
      },
    );
  };

  return (
    <section className="sid-profile" aria-label="Identity profile">
      <h2 className="sid-profile__title">Identity</h2>
      <dl className="sid-profile__fields">
        <div>
          <dt>DID</dt>
          <dd className="sid-profile__did">{document.id}</dd>
        </div>
        <div>
          <dt>Status</dt>
          <dd>{deactivated ? "Deactivated" : "Active"}</dd>
        </div>
      </dl>

      {wantsEdit && deactivated ? (
        <p className="sid-profile__deactivated-note" role="note">
          This identity is deactivated and cannot be modified.
        </p>
      ) : null}

      <div className="sid-profile__live" aria-live="polite" aria-atomic="true">
        {mutation.status === "pending" ? (
          <p className="sid-profile__status sid-profile__status--pending" role="status">
            {mutation.message}
          </p>
        ) : null}
        {mutation.status === "success" ? (
          <p className="sid-profile__status sid-profile__status--success" role="status">
            {mutation.message}
          </p>
        ) : null}
        {mutation.status === "error" ? (
          <p className="sid-profile__status sid-profile__status--error" role="alert">
            {mutation.message}
          </p>
        ) : null}
        {status === "error" && error !== null ? (
          <p className="sid-profile__status sid-profile__status--error" role="alert">
            Could not refresh {did}: {error.message}
          </p>
        ) : null}
      </div>

      <h3>Verification methods</h3>
      {document.verificationMethod.length === 0 ? (
        <p className="sid-profile__empty">None.</p>
      ) : (
        <ul className="sid-profile__list">
          {document.verificationMethod.map((vm) => {
            const fragmentId = extractFragmentId(vm.id, document.id);
            const isConfirming =
              confirming?.kind === "key" && confirming.fragmentId === fragmentId;
            const relationships: string[] = [];
            if (authSet.has(fragmentId)) {
              relationships.push("authentication");
            }
            if (assertionSet.has(fragmentId)) {
              relationships.push("assertionMethod");
            }
            return (
              <li key={vm.id} className="sid-profile__item">
                <div className="sid-profile__item-main">
                  <span className="sid-profile__mono">{vm.id}</span>{" "}
                  <span className="sid-profile__muted">({vm.type})</span>
                  {relationships.length > 0 ? (
                    <span className="sid-profile__tags">
                      {relationships.map((rel) => (
                        <span key={rel} className="sid-profile__tag">
                          {rel}
                        </span>
                      ))}
                    </span>
                  ) : null}
                </div>
                {canEdit ? (
                  isConfirming ? (
                    <div
                      className="sid-profile__confirm"
                      role="group"
                      aria-label={`Confirm removal of verification method ${fragmentId}`}
                      onKeyDown={handleConfirmationKeyDown}
                    >
                      <span className="sid-profile__confirm-text">
                        Remove #{fragmentId}?
                      </span>
                      <button
                        type="button"
                        className="sid-profile__button sid-profile__button--danger"
                        onClick={() => void handleConfirmRemove()}
                        disabled={isMutating}
                      >
                        Confirm remove
                      </button>
                      <button
                        ref={cancelButtonRef}
                        type="button"
                        className="sid-profile__button sid-profile__button--secondary"
                        onClick={cancelConfirmation}
                        disabled={isMutating}
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <button
                      ref={registerRemoveRef(`key:${fragmentId}`)}
                      type="button"
                      className="sid-profile__button sid-profile__button--secondary"
                      aria-label={`Remove verification method ${fragmentId}`}
                      onClick={() => requestRemove("key", fragmentId)}
                      disabled={isMutating}
                    >
                      Remove
                    </button>
                  )
                ) : null}
              </li>
            );
          })}
        </ul>
      )}

      {canEdit ? (
        <form
          className="sid-profile__form"
          aria-label="Add verification method"
          onSubmit={(event) => void handleAddKey(event)}
          noValidate
        >
          {existingKeyFragments.length >= MAX_VERIFICATION_METHODS ? (
            <p className="sid-profile__muted">
              Limit reached ({existingKeyFragments.length}/{MAX_VERIFICATION_METHODS} verification
              methods).
            </p>
          ) : null}
          <div className="sid-profile__form-row">
            <label htmlFor={`${uid}-key-id`} className="sid-profile__label">
              Key ID
            </label>
            <input
              id={`${uid}-key-id`}
              className="sid-profile__input"
              type="text"
              value={keyId}
              onChange={(event) => setKeyId(event.target.value)}
              placeholder="key-2"
              disabled={isMutating}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <div className="sid-profile__form-row">
            <label htmlFor={`${uid}-key-hex`} className="sid-profile__label">
              Public key (64-char hex)
            </label>
            <input
              id={`${uid}-key-hex`}
              className="sid-profile__input sid-profile__mono"
              type="text"
              value={publicKeyHex}
              onChange={(event) => setPublicKeyHex(event.target.value)}
              placeholder="64 hexadecimal characters"
              disabled={isMutating}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <fieldset className="sid-profile__fieldset" disabled={isMutating}>
            <legend className="sid-profile__legend">Relationships</legend>
            <label className="sid-profile__checkbox">
              <input
                type="checkbox"
                checked={includeAuthentication}
                onChange={(event) => setIncludeAuthentication(event.target.checked)}
              />
              <span>Authentication</span>
            </label>
            <label className="sid-profile__checkbox">
              <input
                type="checkbox"
                checked={includeAssertionMethod}
                onChange={(event) => setIncludeAssertionMethod(event.target.checked)}
              />
              <span>Assertion method</span>
            </label>
          </fieldset>
          <div className="sid-profile__form-actions">
            <button
              type="submit"
              className="sid-profile__button sid-profile__button--primary"
              disabled={isMutating}
              aria-busy={isMutating}
            >
              Add verification method
            </button>
          </div>
        </form>
      ) : null}

      <h3>Services</h3>
      {document.service.length === 0 ? (
        <p className="sid-profile__empty">None.</p>
      ) : (
        <ul className="sid-profile__list">
          {document.service.map((svc) => {
            const fragmentId = extractFragmentId(svc.id, document.id);
            const isConfirming =
              confirming?.kind === "service" && confirming.fragmentId === fragmentId;
            return (
              <li key={svc.id} className="sid-profile__item">
                <div className="sid-profile__item-main">
                  <span className="sid-profile__mono">{svc.id}</span>{" "}
                  <span className="sid-profile__muted">({svc.type})</span>{" "}
                  <a href={svc.serviceEndpoint} target="_blank" rel="noreferrer">
                    {svc.serviceEndpoint}
                  </a>
                </div>
                {canEdit ? (
                  isConfirming ? (
                    <div
                      className="sid-profile__confirm"
                      role="group"
                      aria-label={`Confirm removal of service ${fragmentId}`}
                      onKeyDown={handleConfirmationKeyDown}
                    >
                      <span className="sid-profile__confirm-text">
                        Remove #{fragmentId}?
                      </span>
                      <button
                        type="button"
                        className="sid-profile__button sid-profile__button--danger"
                        onClick={() => void handleConfirmRemove()}
                        disabled={isMutating}
                      >
                        Confirm remove
                      </button>
                      <button
                        ref={cancelButtonRef}
                        type="button"
                        className="sid-profile__button sid-profile__button--secondary"
                        onClick={cancelConfirmation}
                        disabled={isMutating}
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <button
                      ref={registerRemoveRef(`service:${fragmentId}`)}
                      type="button"
                      className="sid-profile__button sid-profile__button--secondary"
                      aria-label={`Remove service ${fragmentId}`}
                      onClick={() => requestRemove("service", fragmentId)}
                      disabled={isMutating}
                    >
                      Remove
                    </button>
                  )
                ) : null}
              </li>
            );
          })}
        </ul>
      )}

      {canEdit ? (
        <form
          className="sid-profile__form"
          aria-label="Add service"
          onSubmit={(event) => void handleAddService(event)}
          noValidate
        >
          {existingServiceFragments.length >= MAX_SERVICES ? (
            <p className="sid-profile__muted">
              Limit reached ({existingServiceFragments.length}/{MAX_SERVICES} services).
            </p>
          ) : null}
          <div className="sid-profile__form-row">
            <label htmlFor={`${uid}-svc-id`} className="sid-profile__label">
              Service ID
            </label>
            <input
              id={`${uid}-svc-id`}
              className="sid-profile__input"
              type="text"
              value={serviceId}
              onChange={(event) => setServiceId(event.target.value)}
              placeholder="website"
              disabled={isMutating}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <div className="sid-profile__form-row">
            <label htmlFor={`${uid}-svc-kind`} className="sid-profile__label">
              Service type
            </label>
            <input
              id={`${uid}-svc-kind`}
              className="sid-profile__input"
              type="text"
              value={serviceKind}
              onChange={(event) => setServiceKind(event.target.value)}
              placeholder="LinkedDomains"
              disabled={isMutating}
              autoComplete="off"
            />
          </div>
          <div className="sid-profile__form-row">
            <label htmlFor={`${uid}-svc-endpoint`} className="sid-profile__label">
              Service endpoint (https://)
            </label>
            <input
              id={`${uid}-svc-endpoint`}
              className="sid-profile__input sid-profile__mono"
              type="text"
              inputMode="url"
              value={serviceEndpoint}
              onChange={(event) => setServiceEndpoint(event.target.value)}
              placeholder="https://example.com"
              disabled={isMutating}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <div className="sid-profile__form-actions">
            <button
              type="submit"
              className="sid-profile__button sid-profile__button--primary"
              disabled={isMutating}
              aria-busy={isMutating}
            >
              Add service
            </button>
          </div>
        </form>
      ) : null}
    </section>
  );
}

/**
 * Session-aware profile: shows the session DID unless `did` is given, and
 * automatically supplies the authenticated session signer when viewing the
 * active session's own DID.
 *
 * @param props - Optional DID override, network, signer, and injected resolver/updater.
 */
export function IdentityProfile({
  did: didProp,
  network,
  resolve,
  signer: signerProp,
  editable,
  update,
  onUpdated,
}: IdentityProfileProps): React.JSX.Element {
  const { did: sessionDid, status } = useIdentity();
  const sessionSigner = useSessionSigner();
  const targetDid = didProp ?? sessionDid;
  const effectiveSigner =
    signerProp !== undefined
      ? signerProp
      : status === "authenticated" && targetDid !== null && targetDid === sessionDid
        ? sessionSigner
        : null;
  return (
    <IdentityProfileView
      did={targetDid}
      network={network}
      resolve={resolve}
      signer={effectiveSigner}
      editable={editable}
      update={update}
      onUpdated={onUpdated}
    />
  );
}
