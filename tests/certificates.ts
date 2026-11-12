import forge from "node-forge";
import type { RawExtension } from "../src/certificate.ts";
import { buildSelfSigned, textExtension } from "../src/self-signed.ts";

const { asn1 } = forge;

const utf8 = (text: string) =>
  asn1.create(
    asn1.Class.UNIVERSAL,
    asn1.Type.UTF8,
    false,
    forge.util.encodeUtf8(text)
  );

// forge keeps a context-specific tag's number in `type`: [0] is NONE.
const CONTEXT_TAG_0 = asn1.Type.NONE;

/** A Subject Alternative Name with `otherName` entries, as Uanataca does. */
export const subjectAltName = (
  entries: [oid: string, text: string][]
): RawExtension => ({
  id: "2.5.29.17",
  value: asn1
    .toDer(
      asn1.create(
        asn1.Class.UNIVERSAL,
        asn1.Type.SEQUENCE,
        true,
        entries.map(([oid, text]) =>
          asn1.create(asn1.Class.CONTEXT_SPECIFIC, CONTEXT_TAG_0, true, [
            asn1.create(
              asn1.Class.UNIVERSAL,
              asn1.Type.OID,
              false,
              asn1.oidToDer(oid).getBytes()
            ),
            asn1.create(asn1.Class.CONTEXT_SPECIFIC, CONTEXT_TAG_0, true, [
              utf8(text),
            ]),
          ])
        )
      )
    )
    .getBytes(),
});

/** How many distinct key pairs tests draw from. */
const TEST_KEY_SLOTS = 3;
const keyPairs: forge.pki.rsa.KeyPair[] = [];

/**
 * One of a few RSA-2048 key pairs, generated once per test process the first
 * time each is asked for. Generating keys is what makes building a
 * certificate slow (and, with every package's tests running at once, slow
 * enough to time out), so tests that build many certificates certify these
 * instead of a fresh pair each. A test that needs two certificates with
 * different keys asks for two slots.
 */
export const testKeys = (slot = 0) => {
  if (!Number.isInteger(slot) || slot < 0 || slot >= TEST_KEY_SLOTS) {
    throw new RangeError(`There are ${TEST_KEY_SLOTS} test key slots`);
  }

  keyPairs[slot] ??= forge.pki.rsa.generateKeyPair({ bits: 2048 });

  return keyPairs[slot];
};

/** The CAs' own names, as their certificates write them. */
const ISSUERS = {
  "security-data": {
    issuer: [
      { name: "countryName", value: "EC" },
      { name: "organizationName", value: "SECURITY DATA S.A. 2" },
      {
        name: "organizationalUnitName",
        value: "ENTIDAD DE CERTIFICACION DE INFORMACION",
      },
      {
        name: "commonName",
        value: "AUTORIDAD DE CERTIFICACION SUBCA-2 SECURITY DATA",
      },
    ],
    subjectUnit: [
      {
        name: "organizationalUnitName",
        value: "ENTIDAD DE CERTIFICACION DE INFORMACION",
      },
      { name: "organizationName", value: "SECURITY DATA S.A. 2" },
    ],
  },
  uanataca: {
    issuer: [
      { name: "commonName", value: "UANATACA ECUADOR CA 2 2021" },
      { name: "organizationName", value: "UANATACA ECUADOR S.A." },
      { name: "countryName", value: "EC" },
    ],
    subjectUnit: [],
  },
};

/**
 * A certificate identifying a holder the way a given CA does: Security Data
 * with private extensions, Uanataca with SAN `otherName`s. It certifies the
 * first of `testKeys`.
 */
export const createCaStyleCertificate = ({
  ca,
  ruc,
  cedula,
  holderName = "HOLDER",
  password,
  now,
}: {
  ca: "security-data" | "uanataca";
  ruc?: string;
  cedula?: string;
  holderName?: string;
  password: string;
  now?: Date;
}) => {
  const arc =
    ca === "security-data" ? "1.3.6.1.4.1.37746" : "1.3.6.1.4.1.47286.102";

  const fields: [string, string][] = [];

  if (cedula !== undefined && cedula !== "") {
    fields.push([`${arc}.3.1`, cedula]);
  }

  if (ruc !== undefined && ruc !== "") {
    fields.push([`${arc}.3.11`, ruc]);
  }

  return buildSelfSigned({
    commonName: holderName,
    extensions:
      ca === "security-data"
        ? fields.map(([oid, text]) => textExtension(oid, text))
        : [subjectAltName(fields)],
    issuer: ISSUERS[ca].issuer,
    keys: testKeys(),
    now,
    password,
    subject: [
      { name: "commonName", value: holderName },
      ...(cedula === undefined
        ? []
        : [{ name: "serialNumber", value: `${cedula}-200224172048` }]),
      ...ISSUERS[ca].subjectUnit,
      { name: "countryName", value: "EC" },
    ],
    validDays: 730,
  });
};
