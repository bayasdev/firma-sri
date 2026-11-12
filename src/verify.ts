import { DOMParser, onErrorStopParsing, XMLSerializer } from "@xmldom/xmldom";
import type { Element } from "@xmldom/xmldom";
import forge from "node-forge";
import { SignedXml } from "xml-crypto";
import { describeCertificate } from "./certificate.ts";
import type { CertificateInfo } from "./certificate.ts";

const DSIG = "http://www.w3.org/2000/09/xmldsig#";

/** The document carries no valid signature: missing, altered, or not covering it. */
export class SignatureError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SignatureError";
  }
}

export interface VerifiedSignature {
  /** The certificate embedded in the signature, which verified it. */
  certificate: CertificateInfo;
  /** `SigningTime` from the signed XAdES properties, when present. */
  signingTime: Date | null;
}

/** Descendants of an element with this local name, in any namespace. */
const byLocalName = (element: Element, name: string) => [
  ...element.getElementsByTagNameNS("*", name),
];

const DOCTYPE = /<!DOCTYPE/iu;

const rootOf = (xml: string): Element => {
  // The signature covers the root, not the prologue, so nothing else would
  // stop a DTD and the entities it declares.
  if (DOCTYPE.test(xml)) {
    throw new SignatureError("The XML declares a DOCTYPE");
  }

  let root: Element | null;

  try {
    // Anything the parser calls an error stops it, where its default is to
    // log it and go on with what it could read.
    root = new DOMParser({ onError: onErrorStopParsing }).parseFromString(
      xml,
      "text/xml"
    ).documentElement;
  } catch (error) {
    throw new SignatureError("The XML is malformed", { cause: error });
  }

  if (!root) {
    throw new SignatureError("The XML has no root");
  }

  return root;
};

/** The one signature, a child of the root. */
const envelopedSignature = (root: Element): Element => {
  const signatures = [...root.getElementsByTagNameNS(DSIG, "Signature")];
  const [signature] = signatures;

  if (!signature || signatures.length > 1 || signature.parentNode !== root) {
    throw new SignatureError("Expected one enveloped signature");
  }

  return signature;
};

/**
 * Checks every reference's digest and the signature value against the
 * certificate the signature embeds; returns that certificate and the
 * references it signs.
 */
const checkSignature = (xml: string, signature: Element) => {
  // The verifier hands over the certificate it verified with.
  const embedded: string[] = [];

  const verifier = new SignedXml({
    getCertFromKeyInfo: (keyInfo) => {
      const pem = SignedXml.getCertFromKeyInfo(keyInfo);

      if (pem !== null) {
        embedded.push(pem);
      }

      return pem;
    },
  });

  try {
    verifier.loadSignature(new XMLSerializer().serializeToString(signature));

    if (!verifier.checkSignature(xml)) {
      throw new SignatureError("The signature doesn't verify");
    }
  } catch (error) {
    throw error instanceof SignatureError
      ? error
      : new SignatureError("The signature doesn't verify", { cause: error });
  }

  const [pem] = embedded;

  if (pem === undefined) {
    throw new SignatureError("The signature embeds no certificate");
  }

  return {
    pem,
    signed: new Set(verifier.getReferences().map((ref) => ref.uri)),
  };
};

/** `SigningTime` from the signed XAdES properties, when it holds a date. */
const signingTimeOf = (properties: Element): Date | null => {
  const [time] = byLocalName(properties, "SigningTime");
  const text = time?.textContent ?? "";
  const signingTime = new Date(text);

  return text === "" || Number.isNaN(signingTime.getTime())
    ? null
    : signingTime;
};

const verified = (xml: string): VerifiedSignature => {
  const root = rootOf(xml);
  const signature = envelopedSignature(root);
  const { pem, signed } = checkSignature(xml, signature);
  const rootId = root.getAttribute("id");

  if (rootId === null || !signed.has(`#${rootId}`)) {
    throw new SignatureError("The signature doesn't cover the document");
  }

  const [properties] = byLocalName(signature, "SignedProperties");
  const propertiesId = properties?.getAttribute("Id") ?? null;

  if (
    properties === undefined ||
    propertiesId === null ||
    !signed.has(`#${propertiesId}`)
  ) {
    throw new SignatureError("The XAdES properties aren't signed");
  }

  return {
    certificate: describeCertificate(forge.pki.certificateFromPem(pem)),
    signingTime: signingTimeOf(properties),
  };
};

/**
 * Verifies a document's enveloped XAdES-BES signature, as the SRI's profile
 * signs it: exactly one signature, a child of the root; every reference's
 * digest (the document, `SignedProperties`, `KeyInfo`) and the signature
 * value checked against the certificate embedded in it; one reference
 * covering the whole document by its root `id`; and the XAdES properties,
 * whose `SigningTime` it returns, among the signed references.
 *
 * It shows who signed and that nothing changed since. It doesn't show that
 * the SRI authorized the document, nor that the certificate chains to an
 * accredited CA; the caller checks whose certificate it is.
 */
export const verifySignature = (xml: string): VerifiedSignature => {
  try {
    return verified(xml);
  } catch (error) {
    // A document nested past the stack overflows the tree walks, which no
    // reader should see as anything but an unverifiable signature.
    throw error instanceof SignatureError
      ? error
      : new SignatureError("The signature can't be read", { cause: error });
  }
};
