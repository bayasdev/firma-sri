import type forge from "node-forge";

type Attribute = forge.pki.CertificateField;

/** Whether the holder is a person or one who represents a company. */
export const CERTIFICATE_KINDS = [
  "natural_person",
  "legal_representative",
] as const;

export type CertificateKind = (typeof CERTIFICATE_KINDS)[number];

// X.520 attribute types (RFC 4519).
const COMMON_NAME = "2.5.4.3";
const SERIAL_NUMBER = "2.5.4.5";
const ORGANIZATION = "2.5.4.10";

/** RFC 4514 section 2.4: the characters a value can't carry unescaped. */
const escapeValue = (value: string) =>
  value
    .replaceAll(/[\\,+"<>;]/gu, (character) => `\\${character}`)
    .replace(/^[ #]/u, (character) => `\\${character}`)
    .replace(/ $/u, "\\ ");

const textOf = (attribute: Attribute) =>
  (Array.isArray(attribute.value)
    ? attribute.value.join(",")
    : (attribute.value ?? "")
  ).trim();

/** The first non-blank value of an attribute type. */
const valueOf = (attributes: Attribute[], type: string) =>
  attributes
    .flatMap((attribute) =>
      attribute.type === type ? [textOf(attribute)] : []
    )
    .find((value) => value !== "");

/**
 * A distinguished name in RFC 4514 form, such as `CN=MARIA, O=ACME\, S.A.`:
 * a comma inside a value is escaped, so the string still reads back.
 */
export const formatDistinguishedName = (attributes: Attribute[]) =>
  attributes
    .map(
      (attribute) =>
        `${attribute.shortName ?? attribute.name ?? attribute.type}=${escapeValue(textOf(attribute))}`
    )
    .join(", ");

/**
 * The issuer as a signature's `X509IssuerName` names it: RFC 4514, so the
 * last RDN first and the country last, no space after the commas, and `E`
 * spelled `EMAILADDRESS`, the keyword Java's `X500Principal` reads, since the
 * SRI's verifier parses the name with it. Values are kept as the certificate
 * has them, escaped, never trimmed.
 */
export const signatureIssuerName = (issuer: Attribute[]) =>
  issuer
    .toReversed()
    .map((attribute) => {
      const name =
        attribute.shortName === "E"
          ? "EMAILADDRESS"
          : (attribute.shortName ?? attribute.type);

      const value = Array.isArray(attribute.value)
        ? attribute.value.join(",")
        : (attribute.value ?? "");

      return `${name}=${escapeValue(value)}`;
    })
    .join(",");

/** The holder's name: the subject's common name. */
export const holderName = (subject: Attribute[]) =>
  valueOf(subject, COMMON_NAME);

export interface Holder {
  cedula?: string;
  ruc?: string;
}

/**
 * The holder's cédula (10 digits) or RUC (13) from the subject's
 * `serialNumber`, where CAs such as Security Data write `1710034065-200224…`
 * and others prefix a document type (`IDCEC-…`).
 */
const SERIAL_IDENTIFICATION = /^(?:[A-Za-z]+-)?(?<digits>\d{10}|\d{13})(?!\d)/u;

export const serialIdentification = (subject: Attribute[]): Holder => {
  const digits = SERIAL_IDENTIFICATION.exec(
    valueOf(subject, SERIAL_NUMBER) ?? ""
  )?.groups?.digits;

  if (digits === undefined) {
    return {};
  }

  return digits.length === 10 ? { cedula: digits } : { ruc: digits };
};

/**
 * Who the certificate identifies: the person's cédula when there is one, else
 * the RUC. A RUC other than the person's own cédula + `001` means the person
 * represents that company.
 */
export const identifyHolder = ({ cedula, ruc }: Holder) => {
  let kind: CertificateKind | null = null;

  if (cedula !== undefined) {
    kind =
      ruc !== undefined && ruc !== `${cedula}001`
        ? "legal_representative"
        : "natural_person";
  }

  return { identification: cedula ?? ruc ?? null, kind };
};

const LEGAL_FORM =
  /[\s,]+(?:S\.?\s?A\.?S?\.?|C[IÍ]A\.?\s*LTDA\.?|LTDA\.?)(?=\s*\d*$)/iu;

const SMALL_WORDS = new Set(["de", "del", "la", "las", "los", "el", "y", "e"]);

const capitalize = (word: string) =>
  `${word.charAt(0).toUpperCase()}${word.slice(1)}`;

const titleWord = (word: string, index: number) => {
  if (index > 0 && SMALL_WORDS.has(word)) {
    return word;
  }

  // Short words are acronyms here: ANF, AC.
  return word.length <= 3 ? word.toUpperCase() : capitalize(word);
};

const withoutLegalForm = (name: string): string => {
  const plain = name
    .replace(LEGAL_FORM, "")
    .replace(/\s+\d+$/u, "")
    .trim();

  return plain === name ? name : withoutLegalForm(plain);
};

/**
 * A CA's name as people say it: `SECURITY DATA S.A. 2` is "Security Data".
 * Drops the legal form and trailing number, and writes all-capitals names in
 * title case (keeping short acronyms such as ANF).
 */
export const normalizeOrganization = (name: string) => {
  const plain = withoutLegalForm(name.replaceAll(/\s+/gu, " ").trim());

  return plain === plain.toUpperCase()
    ? plain.toLowerCase().split(" ").map(titleWord).join(" ")
    : plain;
};

/** The issuing CA's name: its organization, else its common name. */
export const issuerName = (issuer: Attribute[]) => {
  const name = valueOf(issuer, ORGANIZATION) ?? valueOf(issuer, COMMON_NAME);

  return name === undefined ? undefined : normalizeOrganization(name);
};
