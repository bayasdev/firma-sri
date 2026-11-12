import forge from "node-forge";
import {
  formatDistinguishedName,
  holderName,
  identifyHolder,
  issuerName,
  serialIdentification,
} from "./certificate-names.ts";
import type { CertificateKind } from "./certificate-names.ts";

export interface CertificateInfo {
  /** Who the certificate identifies, from the CA's own fields. */
  holder: { ruc?: string; cedula?: string };
  /** The holder's name, as the subject's common name says it. */
  holderName: string | null;
  /** The holder's cédula, or their RUC when the certificate has no cédula. */
  holderIdentification: string | null;
  /** The issuing CA as people name it: "Security Data". */
  issuerName: string | null;
  issuer: string;
  /** Whether the holder is a person or represents a company, when the CA says. */
  kind: CertificateKind | null;
  /**
   * Whether its key may sign: `keyUsage` names digital signature, or the
   * certificate restricts no use (RFC 5280, section 4.2.1.3). The SRI's
   * offline invoicing tool refuses a certificate without it.
   */
  canSign: boolean;
  notAfter: Date;
  notBefore: Date;
  serialNumber: string;
  subject: string;
}

/**
 * Where each CA accredited in Ecuador records the holder's cédula and RUC.
 * Most use a private certificate extension under their arc; Uanataca and
 * Eclipsoft use an `otherName` in the Subject Alternative Name. Source: the
 * government's FirmaEC library, `ec.gob.firmadigital.libreria.certificate.ec`.
 */
const CA_HOLDER_OIDS = [
  {
    ca: "Banco Central del Ecuador",
    cedula: "1.3.6.1.4.1.37947.3.1",
    ruc: "1.3.6.1.4.1.37947.3.11",
  },
  {
    ca: "Security Data",
    cedula: "1.3.6.1.4.1.37746.3.1",
    ruc: "1.3.6.1.4.1.37746.3.11",
  },
  {
    ca: "ANF AC",
    cedula: "1.3.6.1.4.1.18332.3.1",
    ruc: "1.3.6.1.4.1.18332.3.11",
  },
  {
    ca: "ANF AC (2019)",
    cedula: "1.3.6.1.4.1.37442.3.1",
    ruc: "1.3.6.1.4.1.37442.3.11",
  },
  {
    ca: "Consejo de la Judicatura",
    cedula: "1.3.6.1.4.1.43745.1.3.1",
    ruc: "1.3.6.1.4.1.43745.1.3.11",
  },
  {
    ca: "Registro Civil (DIGERCIC)",
    cedula: "1.3.6.1.4.1.55519.1.1.1.5.2.1",
    ruc: "1.3.6.1.4.1.55519.1.1.1.5.2.4",
  },
  {
    ca: "Uanataca",
    cedula: "1.3.6.1.4.1.47286.102.3.1",
    ruc: "1.3.6.1.4.1.47286.102.3.11",
  },
  {
    ca: "Eclipsoft",
    cedula: "1.3.6.1.4.1.57153.102.3.1",
    ruc: "1.3.6.1.4.1.57153.102.3.11",
  },
  {
    ca: "Datilmedia",
    cedula: "1.3.6.1.4.1.52643.3.1",
    ruc: "1.3.6.1.4.1.52643.3.11",
  },
  {
    ca: "Lazzate",
    cedula: "1.3.6.1.4.1.59382.3.1",
    ruc: "1.3.6.1.4.1.59382.3.11",
  },
  {
    ca: "Argos Data",
    cedula: "1.3.6.1.4.1.59198.3.1",
    ruc: "1.3.6.1.4.1.59198.3.11",
  },
  {
    ca: "Alpha Technologies",
    cedula: "1.3.6.1.4.1.56105.3.1",
    ruc: "1.3.6.1.4.1.56105.3.11",
  },
  {
    ca: "FirmaSegura",
    cedula: "1.3.6.1.4.1.61305.3.1",
    ruc: "1.3.6.1.4.1.61305.3.11",
  },
  {
    ca: "CorpNewBest",
    cedula: "1.3.6.1.4.1.34380.3.1",
    ruc: "1.3.6.1.4.1.34380.3.11",
  },
] as const;

/** The holder's cédula and RUC OIDs of every accredited CA, in the same order. */
const HOLDER_OIDS = {
  cedula: CA_HOLDER_OIDS.map((ca) => ca.cedula),
  ruc: CA_HOLDER_OIDS.map((ca) => ca.ruc),
};

const SUBJECT_ALT_NAME = "2.5.29.17";

// forge keeps a context-specific tag's number in `type`: `otherName` is [0].
const OTHER_NAME_TAG = forge.asn1.Type.NONE;

/** A certificate extension forge can encode: an OID and its DER value. */
export interface RawExtension {
  id: string;
  value: string;
}

const isRawExtension = (extension: unknown): extension is RawExtension =>
  typeof extension === "object" &&
  extension !== null &&
  "id" in extension &&
  "value" in extension &&
  typeof extension.id === "string" &&
  typeof extension.value === "string";

/** Decodes a DER string value (UTF8String, PrintableString, IA5String …). */
const asn1Text = (node: forge.asn1.Asn1): string | undefined => {
  if (Array.isArray(node.value)) {
    return undefined;
  }

  return node.type === forge.asn1.Type.UTF8
    ? forge.util.decodeUtf8(node.value)
    : node.value;
};

/** `otherName ::= [0] { type-id OID, [0] EXPLICIT value }` entries of a SAN. */
const otherNames = (subjectAltName: string): [string, string][] => {
  const names = forge.asn1.fromDer(subjectAltName).value;

  return (Array.isArray(names) ? names : []).flatMap((name) => {
    const [typeId, wrapper] = Array.isArray(name.value) ? name.value : [];
    const inner = Array.isArray(wrapper?.value) ? wrapper.value[0] : undefined;
    const text = inner ? asn1Text(inner) : undefined;

    const oid =
      typeId === undefined || Array.isArray(typeId.value)
        ? undefined
        : typeId.value;

    return name.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC &&
      name.type === OTHER_NAME_TAG &&
      oid !== undefined &&
      text !== undefined &&
      text !== ""
      ? [[forge.asn1.derToOid(oid), text.trim()]]
      : [];
  });
};

/**
 * Every OID-keyed text value in private extensions and SAN `otherName`s. A
 * private extension wins over an `otherName` with its OID, whichever comes
 * first, as the SRI's offline invoicing tool reads the RUC.
 */
const oidValues = (certificate: forge.pki.Certificate) => {
  const fromNames = new Map<string, string>();
  const fromExtensions = new Map<string, string>();

  for (const extension of certificate.extensions.filter(isRawExtension)) {
    try {
      if (extension.id === SUBJECT_ALT_NAME) {
        for (const [oid, text] of otherNames(extension.value)) {
          fromNames.set(oid, text);
        }

        continue;
      }

      const text = asn1Text(forge.asn1.fromDer(extension.value));

      if (text !== undefined && text !== "") {
        fromExtensions.set(extension.id, text.trim());
      }
    } catch {
      // Not a text value; nothing to read.
    }
  }

  return new Map([...fromNames, ...fromExtensions]);
};

const firstOf = (values: Map<string, string>, oids: readonly string[]) =>
  oids.map((oid) => values.get(oid)).find((value) => value !== undefined);

/**
 * Whether a certificate identifies the taxpayer with this RUC: its RUC field,
 * or for a natural person, the cédula plus `001`.
 */
export const certificateHolds = (info: CertificateInfo, ruc: string) =>
  info.holder.ruc === ruc ||
  (info.holder.cedula !== undefined && `${info.holder.cedula}001` === ruc);

// PKCS#12 bag types (RFC 7292, section 4.2).
const KEY_BAG = "1.2.840.113549.1.12.10.1.1";
const SHROUDED_KEY_BAG = "1.2.840.113549.1.12.10.1.2";
const CERT_BAG = "1.2.840.113549.1.12.10.1.3";

/** Why a file can't be read as a certificate. */
export type CertificateErrorReason =
  | "not_pkcs12"
  | "wrong_password"
  | "no_private_key";

export class CertificateError extends Error {
  readonly reason: CertificateErrorReason;

  constructor(
    message: string,
    reason: CertificateErrorReason,
    options?: ErrorOptions
  ) {
    super(message, options);
    this.name = "CertificateError";
    this.reason = reason;
  }
}

const isRsa = (key: forge.pki.PublicKey): key is forge.pki.rsa.PublicKey =>
  "n" in key;

const holderOf = (certificate: forge.pki.Certificate) => {
  const values = oidValues(certificate);
  const holder: CertificateInfo["holder"] = {};
  const ruc = firstOf(values, HOLDER_OIDS.ruc);

  if (ruc !== undefined && ruc !== "") {
    holder.ruc = ruc;
  }

  const cedula = firstOf(values, HOLDER_OIDS.cedula);

  if (cedula !== undefined && cedula !== "") {
    holder.cedula = cedula;
  }

  return holder;
};

/** Whether a certificate's key may sign: `keyUsage` absent, or naming digital signature (RFC 5280, section 4.2.1.3). */
const canSignWith = (certificate: forge.pki.Certificate) => {
  const usage = certificate.getExtension("keyUsage");

  return (
    usage === undefined ||
    usage === null ||
    ("digitalSignature" in usage && usage.digitalSignature === true)
  );
};

/**
 * What a certificate says: who holds it (by the CA's own fields), who issued
 * it and when it's valid. A .p12 file and the signature on a signed document
 * are read the same way.
 */
export const describeCertificate = (
  certificate: forge.pki.Certificate
): CertificateInfo => {
  const holder = holderOf(certificate);

  const { identification, kind } = identifyHolder({
    ...serialIdentification(certificate.subject.attributes),
    ...holder,
  });

  return {
    canSign: canSignWith(certificate),
    holder,
    holderIdentification: identification,
    holderName: holderName(certificate.subject.attributes) ?? null,
    issuer: formatDistinguishedName(certificate.issuer.attributes),
    issuerName: issuerName(certificate.issuer.attributes) ?? null,
    kind,
    notAfter: certificate.validity.notAfter,
    notBefore: certificate.validity.notBefore,
    serialNumber: certificate.serialNumber,
    subject: formatDistinguishedName(certificate.subject.attributes),
  };
};

/** A PKCS#12 file's private key and the certificate that goes with it. */
export interface Pkcs12Contents {
  key: forge.pki.rsa.PrivateKey;
  certificate: forge.pki.Certificate;
}

/**
 * Opens a PKCS#12 file (.p12, legacy RC2/3DES or modern AES): its first
 * private key, and the certificate whose public key matches it, wherever the
 * file puts the CA's chain.
 */
export const openPkcs12 = (
  p12: Uint8Array,
  password: string
): Pkcs12Contents => {
  let pfx: forge.asn1.Asn1;

  try {
    pfx = forge.asn1.fromDer(forge.util.binary.raw.encode(p12));
  } catch (error) {
    throw new CertificateError(
      "The file isn't a PKCS#12 certificate",
      "not_pkcs12",
      { cause: error }
    );
  }

  let store: forge.pkcs12.Pkcs12Pfx;

  try {
    store = forge.pkcs12.pkcs12FromAsn1(pfx, password);
  } catch (error) {
    // The structure parses but won't open: forge says "Invalid password?"
    // when the MAC or the key's encryption fails; anything else is a file
    // that isn't a PKCS#12 after all.
    const wrong = error instanceof Error && /password/iu.test(error.message);
    throw new CertificateError(
      wrong
        ? "The certificate's password is wrong"
        : "The file isn't a PKCS#12 certificate",
      wrong ? "wrong_password" : "not_pkcs12",
      { cause: error }
    );
  }

  const bags = (type: string) => store.getBags({ bagType: type })[type] ?? [];
  const key = [...bags(SHROUDED_KEY_BAG), ...bags(KEY_BAG)][0]?.key;

  const certificate = bags(CERT_BAG)
    .map((bag) => bag.cert)
    .find(
      (cert): cert is forge.pki.Certificate =>
        cert !== undefined &&
        key !== undefined &&
        isRsa(cert.publicKey) &&
        cert.publicKey.n.equals(key.n)
    );

  if (!certificate || !key) {
    throw new CertificateError(
      "The file has no private key with its certificate",
      "no_private_key"
    );
  }

  return { certificate, key };
};

/** Opens a PKCS#12 file and describes the certificate that goes with its private key. */
export const readCertificate = (
  p12: Uint8Array,
  password: string
): CertificateInfo =>
  describeCertificate(openPkcs12(p12, password).certificate);
