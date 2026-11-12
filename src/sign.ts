import { createHash, createSign, randomUUID } from "node:crypto";
import { assertIsElementNode } from "@xmldom/is-dom-node";
import { DOMParser } from "@xmldom/xmldom";
import forge from "node-forge";
import { C14nCanonicalization } from "xml-crypto";
import { signatureIssuerName } from "./certificate-names.ts";
import { openPkcs12 } from "./certificate.ts";

/** A PKCS#12 file and the password that opens it. */
export interface SigningCertificate {
  p12: Uint8Array;
  password: string;
}

/**
 * The hash of every digest and of the signature. The SRI's ficha técnica
 * (section 6.8) specifies `sha1`; the SRI also authorizes documents signed
 * with `sha256`.
 */
export type SignatureAlgorithm = "sha1" | "sha256";

export interface SignOptions {
  /** `sha1` by default, as the ficha técnica specifies. */
  algorithm?: SignatureAlgorithm;
}

/** Why a document can't be signed. */
export type DocumentErrorReason =
  | "malformed"
  | "doctype"
  | "root_id"
  | "root_namespaces"
  | "already_signed"
  | "trailing_content";

export class DocumentError extends Error {
  readonly reason: DocumentErrorReason;

  constructor(
    message: string,
    reason: DocumentErrorReason,
    options?: ErrorOptions
  ) {
    super(message, options);
    this.name = "DocumentError";
    this.reason = reason;
  }
}

const DSIG = "http://www.w3.org/2000/09/xmldsig#";
const C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

// The identifiers of each hash: XMLDSig core, section 6, for SHA-1; RFC 6931
// (sections 2.1.2 and 2.3.2) for SHA-256.
const ALGORITHMS = {
  sha1: {
    digest: `${DSIG}sha1`,
    node: "RSA-SHA1",
    signature: `${DSIG}rsa-sha1`,
  },
  sha256: {
    digest: "http://www.w3.org/2001/04/xmlenc#sha256",
    node: "RSA-SHA256",
    signature: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  },
} as const;

const ENVELOPED = `${DSIG}enveloped-signature`;

// ETSI TS 101 903 v1.3.2: the namespace, and the Type of the reference to
// the signed properties (section 6.3.1).
const XADES = "http://uri.etsi.org/01903/v1.3.2#";
const SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties";

const DS_DECLARATION = ` xmlns:ds="${DSIG}"`;
const XADES_DECLARATION = ` xmlns:xades="${XADES}"`;

const DOCTYPE = /<!DOCTYPE/iu;

/** Character data as Canonical XML writes it (section 2.3, text nodes). */
const text = (value: string) =>
  value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\r", "&#xD;");

/** A non-negative integer as XMLDSig's CryptoBinary: its big-endian bytes, no leading zero, in base64. */
const cryptoBinary = (integer: forge.jsbn.BigInteger) => {
  const hex = integer.toString(16);

  return forge.util.encode64(
    forge.util.hexToBytes(hex.length % 2 === 0 ? hex : `0${hex}`)
  );
};

/** A serial's hex bytes as the decimal integer DER encodes: two's complement. */
const serialNumber = (hex: string) =>
  BigInt.asIntN(hex.length * 4, BigInt(`0x${hex}`)).toString();

// Mainland Ecuador keeps UTC-5 all year.
const ECUADOR_OFFSET_MS = 5 * 60 * 60 * 1000;

/** The instant on Ecuador's clock, to the second: `2026-10-02T07:51:22-05:00`. */
const signingTime = (now: Date) =>
  `${new Date(now.getTime() - ECUADOR_OFFSET_MS).toISOString().slice(0, 19)}-05:00`;

/**
 * A piece of the signature that a reference or the signature value covers.
 * Canonical XML of an element taken out of its document writes on it the
 * namespace declarations it inherits (section 4.7), so the piece has two
 * spellings: the one that goes into the document, and the one digested.
 */
const piece = (
  inherited: string,
  render: (declarations: string) => string
) => ({
  canonical: render(inherited),
  embedded: render(""),
});

/** An element's Id: its role and a random UUID, unique in any document. */
const id = (role: string) => `${role}-${randomUUID()}`;

/** An element's digest method and value (XMLDSig section 4.4.3). */
const digestOf = (method: string, digest: string) =>
  `<ds:DigestMethod Algorithm="${method}"></ds:DigestMethod><ds:DigestValue>${digest}</ds:DigestValue>`;

const parse = (xml: string) => {
  // A DTD's entities would be signed as text nobody wrote in the document.
  if (DOCTYPE.test(xml)) {
    throw new DocumentError("The document declares a DOCTYPE", "doctype");
  }

  try {
    return new DOMParser().parseFromString(xml, "text/xml").documentElement;
  } catch (error) {
    throw new DocumentError("The document is malformed", "malformed", {
      cause: error,
    });
  }
};

/**
 * The document's root, which the signature goes into, and where its end tag
 * starts. The SRI's schemas put the signature last in the comprobante and
 * its reference points at `id="comprobante"`.
 */
const comprobanteOf = (xml: string) => {
  const root = parse(xml);

  if (root?.getAttribute("id") !== "comprobante") {
    throw new DocumentError(
      'The document\'s root must carry id="comprobante"',
      "root_id"
    );
  }

  // The signature would sit inside those declarations, and each signed piece
  // would have to be digested with them.
  if (
    [...root.attributes].some(
      ({ name }) => name === "xmlns" || name.startsWith("xmlns:")
    )
  ) {
    throw new DocumentError(
      "The document's root declares namespaces",
      "root_namespaces"
    );
  }

  // A second signature would leave the first one covering a document it never
  // signed.
  if (root.getElementsByTagNameNS(DSIG, "Signature").length > 0) {
    throw new DocumentError(
      "The document already carries a signature",
      "already_signed"
    );
  }

  const body = xml.trimEnd();
  const end = body.lastIndexOf("</");
  const endTag = end === -1 ? "" : body.slice(end);
  const closing = /^<\/(?<name>[^\s>]+)\s*>$/u.exec(endTag);

  if (closing?.groups?.name !== root.tagName) {
    throw new DocumentError(
      "The document must end with its root's end tag",
      "trailing_content"
    );
  }

  return { end, root };
};

/**
 * Signs a comprobante as the SRI's profile asks (ficha técnica, section
 * 6.8): one enveloped XAdES-BES signature, RSA-SHA1 over inclusive Canonical
 * XML 1.0 unless `algorithm` says SHA-256, appended as the root's last
 * child. The document's own characters are left as they were.
 *
 * It throws a `DocumentError` for a document it can't sign and a
 * `CertificateError` for a file it can't open. It signs with any certificate
 * the file holds: whether it's expired or may sign is `readCertificate`'s to
 * tell.
 *
 * `SignedInfo` references three things, each with its digest: the
 * document (XMLDSig's enveloped-signature transform), the XAdES signed
 * properties, which name the moment and the certificate (XAdES sections
 * 7.2.1 and 7.2.2), and the `KeyInfo` that embeds that certificate.
 */
export const signXml = (
  xml: string,
  { p12, password }: SigningCertificate,
  { algorithm = "sha1" }: SignOptions = {}
): string => {
  const methods = ALGORITHMS[algorithm];

  const digest = (data: string, encoding: "utf-8" | "latin1" = "utf-8") =>
    createHash(algorithm).update(data, encoding).digest("base64");

  // A `ds:Reference` to something `SignedInfo` covers.
  const reference = (attributes: string, transforms: string, value: string) =>
    `<ds:Reference ${attributes}>${transforms}${digestOf(methods.digest, value)}</ds:Reference>`;

  const { root, end } = comprobanteOf(xml);
  // xmldom's element is one to the canonicalizer, whose types are the DOM's.
  assertIsElementNode(root);
  const { key, certificate } = openPkcs12(p12, password);

  const der = forge.asn1
    .toDer(forge.pki.certificateToAsn1(certificate))
    .getBytes();

  const ids = {
    documentReference: id("DocumentRef"),
    keyInfo: id("Certificate"),
    keyInfoReference: id("CertificateRef"),
    object: id("SignatureObject"),
    properties: id("SignedProperties"),
    propertiesReference: id("SignedPropertiesRef"),
    signature: id("Signature"),
    signatureValue: id("SignatureValue"),
    signedInfo: id("SignedInfo"),
  };

  const keyInfo = piece(
    DS_DECLARATION,
    (declarations) =>
      `<ds:KeyInfo${declarations} Id="${ids.keyInfo}">` +
      `<ds:X509Data><ds:X509Certificate>${forge.util.encode64(der)}</ds:X509Certificate></ds:X509Data>` +
      `<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>${cryptoBinary(key.n)}</ds:Modulus><ds:Exponent>${cryptoBinary(key.e)}</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>` +
      "</ds:KeyInfo>"
  );

  const properties = piece(
    DS_DECLARATION + XADES_DECLARATION,
    (declarations) =>
      `<xades:SignedProperties${declarations} Id="${ids.properties}">` +
      "<xades:SignedSignatureProperties>" +
      `<xades:SigningTime>${signingTime(new Date())}</xades:SigningTime>` +
      "<xades:SigningCertificate><xades:Cert>" +
      `<xades:CertDigest>${digestOf(methods.digest, digest(der, "latin1"))}</xades:CertDigest>` +
      `<xades:IssuerSerial><ds:X509IssuerName>${text(signatureIssuerName(certificate.issuer.attributes))}</ds:X509IssuerName><ds:X509SerialNumber>${serialNumber(certificate.serialNumber)}</ds:X509SerialNumber></xades:IssuerSerial>` +
      "</xades:Cert></xades:SigningCertificate>" +
      "</xades:SignedSignatureProperties>" +
      "<xades:SignedDataObjectProperties>" +
      `<xades:DataObjectFormat ObjectReference="#${ids.documentReference}"><xades:Description>Firma digital</xades:Description><xades:MimeType>text/xml</xades:MimeType><xades:Encoding>UTF-8</xades:Encoding></xades:DataObjectFormat>` +
      "</xades:SignedDataObjectProperties>" +
      "</xades:SignedProperties>"
  );

  // The signature isn't in the document yet, so the root's canonical form
  // is already what the enveloped-signature transform leaves of it.
  const signedInfo = piece(
    DS_DECLARATION,
    (declarations) =>
      `<ds:SignedInfo${declarations} Id="${ids.signedInfo}">` +
      `<ds:CanonicalizationMethod Algorithm="${C14N}"></ds:CanonicalizationMethod>` +
      `<ds:SignatureMethod Algorithm="${methods.signature}"></ds:SignatureMethod>${reference(
        `Id="${ids.documentReference}" URI="#comprobante"`,
        `<ds:Transforms><ds:Transform Algorithm="${ENVELOPED}"></ds:Transform></ds:Transforms>`,
        digest(new C14nCanonicalization().process(root, {}))
      )}${reference(
        `Id="${ids.propertiesReference}" Type="${SIGNED_PROPERTIES_TYPE}" URI="#${ids.properties}"`,
        "",
        digest(properties.canonical)
      )}${reference(
        `Id="${ids.keyInfoReference}" URI="#${ids.keyInfo}"`,
        "",
        digest(keyInfo.canonical)
      )}</ds:SignedInfo>`
  );

  // RSASSA-PKCS1-v1_5 over the hash of the canonical SignedInfo (XMLDSig
  // 6.4.2).
  const signatureValue = createSign(methods.node)
    .update(signedInfo.canonical, "utf-8")
    .sign(forge.pki.privateKeyToPem(key), "base64");

  const signature =
    `<ds:Signature${DS_DECLARATION} Id="${ids.signature}">${signedInfo.embedded}` +
    `<ds:SignatureValue Id="${ids.signatureValue}">${signatureValue}</ds:SignatureValue>${keyInfo.embedded}` +
    `<ds:Object Id="${ids.object}"><xades:QualifyingProperties${XADES_DECLARATION} Target="#${ids.signature}">${properties.embedded}</xades:QualifyingProperties></ds:Object>` +
    "</ds:Signature>";

  return `${xml.slice(0, end)}${signature}${xml.slice(end)}`;
};
