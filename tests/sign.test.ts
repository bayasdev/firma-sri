import { createHash, X509Certificate } from "node:crypto";
import * as hegel from "@hegeldev/hegel";
import * as gs from "@hegeldev/hegel/generators";
import { DOMParser } from "@xmldom/xmldom";
import type { Element } from "@xmldom/xmldom";
import forge from "node-forge";
import { describe, expect, it, vi } from "vitest";
import { readCertificate } from "../src/certificate.ts";
import { buildSelfSigned } from "../src/self-signed.ts";
import { DocumentError, signXml } from "../src/sign.ts";
import type { SignatureAlgorithm } from "../src/sign.ts";
import { SignatureError, verifySignature } from "../src/verify.ts";
import { testKeys } from "./certificates.ts";
import {
  comprobante,
  COMPROBANTES,
  comprobantes,
  drawXml,
} from "./documents.ts";
import { xadesErrors, xsdErrors } from "./xsd.ts";

const PASSWORD = "clave";
const NAME = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .-";

const ALPHANUMERIC =
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

const SIGNATURE = /<ds:Signature[\s\S]*<\/ds:Signature>/u;
const algorithms: SignatureAlgorithm[] = ["sha1", "sha256"];

/** Runs `sign` with the clock at `now`. */
const pinned = (now: Date, sign: () => string) => {
  vi.useFakeTimers({ now, toFake: ["Date"] });

  try {
    return sign();
  } finally {
    vi.useRealTimers();
  }
};

/**
 * A throwaway certificate whose holder and issuer names are drawn, over one
 * of the test key pairs (drawn too, unless `slot` names it).
 */
const drawCertificate = (
  tc: hegel.TestCase,
  {
    slot = tc.draw(gs.integers({ maxValue: 2, minValue: 0 })),
    email = tc.draw(gs.booleans()),
  }: { slot?: number; email?: boolean } = {}
) => {
  const text = () =>
    tc.draw(gs.text({ alphabet: NAME, maxSize: 30, minSize: 1 })).trim() || "X";

  return buildSelfSigned({
    commonName: text(),
    issuer: [
      { name: "countryName", value: "EC" },
      { name: "organizationName", value: text() },
      { name: "organizationalUnitName", value: text() },
      { name: "commonName", value: text() },
      ...(email ? [{ name: "emailAddress", value: "ca@example.com" }] : []),
    ],
    keys: testKeys(slot),
    password: PASSWORD,
  });
};

const drawAlgorithm = (tc: hegel.TestCase) =>
  tc.draw(gs.sampledFrom(algorithms));

const drawInstant = (tc: hegel.TestCase) =>
  new Date(
    tc.draw(
      gs.integers({ maxValue: 2_000_000_000_000, minValue: 1_700_000_000_000 })
    )
  );

const signatureOf = (signed: string) => SIGNATURE.exec(signed)?.[0] ?? "";

const textOf = (signed: string, localName: string) =>
  new DOMParser()
    .parseFromString(signed, "text/xml")
    .getElementsByTagNameNS("*", localName)
    .item(0)?.textContent ?? "";

/** Indexes of the letters and digits in the document's own text, outside tags and entities. */
const textPositions = (signed: string) => {
  const end = signed.indexOf("<ds:Signature");
  const positions: number[] = [];
  let inMarkup = false;

  for (let index = 0; index < end; index += 1) {
    const character = signed.charAt(index);

    if (character === "<" || character === "&") {
      inMarkup = true;
    } else if (character === ">" || character === ";") {
      inMarkup = false;
    } else if (!inMarkup && ALPHANUMERIC.includes(character)) {
      positions.push(index);
    }
  }

  return positions;
};

const DSIG = "http://www.w3.org/2000/09/xmldsig#";
const XADES = "http://uri.etsi.org/01903/v1.3.2#";

/** The signed document's elements named `localName` in `namespace`. */
const elements = (signed: string, namespace: string, localName: string) => {
  const list = new DOMParser()
    .parseFromString(signed, "text/xml")
    .getElementsByTagNameNS(namespace, localName);

  return Array.from({ length: list.length }, (_, index) => list.item(index));
};

const attribute = (element: Element | null, name: string) =>
  element?.getAttribute(name) ?? null;

/** The certificate inside a PKCS#12, read with node-forge rather than the signer. */
const forgeCertificate = (p12: Uint8Array) => {
  const store = forge.pkcs12.pkcs12FromAsn1(
    forge.asn1.fromDer(forge.util.binary.raw.encode(p12)),
    PASSWORD
  );

  const certBag = forge.pki.oids.certBag ?? "";
  const bag = store.getBags({ bagType: certBag })[certBag]?.[0];

  if (!bag?.cert) {
    throw new Error("No certificate in the PKCS#12");
  }

  return bag.cert;
};

// The identifiers of each hash: XMLDSig core, section 6, for SHA-1; RFC 6931,
// sections 2.1.2 and 2.3.2, for SHA-256.
const IDENTIFIERS = {
  sha1: {
    digest: "http://www.w3.org/2000/09/xmldsig#sha1",
    signature: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
  },
  sha256: {
    digest: "http://www.w3.org/2001/04/xmlenc#sha256",
    signature: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  },
};

describe("a signed document", () => {
  it("verifies with its certificate, signed at that moment in Ecuador's time, and keeps every character it had", () => {
    hegel.test(
      (tc) => {
        const xml = drawXml(tc);
        const p12 = drawCertificate(tc);
        const now = drawInstant(tc);

        const signed = pinned(now, () =>
          signXml(
            xml,
            { p12, password: PASSWORD },
            { algorithm: drawAlgorithm(tc) }
          )
        );

        const { certificate, signingTime } = verifySignature(signed);
        expect(certificate).toStrictEqual(readCertificate(p12, PASSWORD));
        // To the second, as the SRI's offline invoicing tool writes it.
        expect(signingTime).toStrictEqual(
          new Date(Math.floor(now.getTime() / 1000) * 1000)
        );
        // Mainland Ecuador keeps UTC-5 all year.
        expect(textOf(signed, "SigningTime")).toMatch(
          /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d-05:00$/u
        );
        // The signature is appended to the document, which stays as it was.
        expect(signed.replace(signatureOf(signed), "")).toBe(xml);
      },
      { testCases: 50 }
    );
  });

  it("keeps an end tag's own spacing, asking only that it be the root's", () => {
    const xml = '<factura id="comprobante"><a>1</a></factura >';

    const signed = signXml(xml, {
      p12: buildSelfSigned({
        commonName: "HOLDER",
        keys: testKeys(0),
        password: PASSWORD,
      }),
      password: PASSWORD,
    });

    expect(signed.replace(signatureOf(signed), "")).toBe(xml);
    expect(() => verifySignature(signed)).not.toThrow();
  });

  describe.each(algorithms)("with %s", (algorithm) => {
    it.each(comprobantes)(
      "a signed %s verifies and is valid against the SRI's XSD for it",
      async (type) => {
        const signed = signXml(
          comprobante(type),
          {
            p12: buildSelfSigned({
              commonName: "HOLDER",
              keys: testKeys(0),
              password: PASSWORD,
            }),
            password: PASSWORD,
          },
          { algorithm }
        );

        expect(() => verifySignature(signed)).not.toThrow();
        await expect(
          xsdErrors(signed, COMPROBANTES[type])
        ).resolves.toStrictEqual([]);
      }
    );

    it("follows the SRI's profile: RSA over C14N, the document enveloped and its properties and key signed", () => {
      hegel.test(
        (tc) => {
          const signed = signXml(
            drawXml(tc),
            { p12: drawCertificate(tc), password: PASSWORD },
            { algorithm }
          );

          const [method] = elements(signed, DSIG, "SignatureMethod");

          const [canonicalization] = elements(
            signed,
            DSIG,
            "CanonicalizationMethod"
          );

          expect(attribute(method ?? null, "Algorithm")).toBe(
            IDENTIFIERS[algorithm].signature
          );
          // Inclusive Canonical XML 1.0, without comments.
          expect(attribute(canonicalization ?? null, "Algorithm")).toBe(
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
          );

          const [properties] = elements(signed, XADES, "SignedProperties");
          const [keyInfo] = elements(signed, DSIG, "KeyInfo");

          const references = elements(signed, DSIG, "Reference").map(
            (reference) => ({
              digest: attribute(
                reference
                  ?.getElementsByTagNameNS(DSIG, "DigestMethod")
                  .item(0) ?? null,
                "Algorithm"
              ),
              transforms: Array.from(
                reference?.getElementsByTagNameNS(DSIG, "Transform") ?? [],
                (transform) => transform.getAttribute("Algorithm")
              ),
              type: attribute(reference, "Type"),
              uri: attribute(reference, "URI"),
            })
          );

          const { digest } = IDENTIFIERS[algorithm];
          // XMLDSig section 6.6.4 names the transform; XAdES 1.3.2 section
          // 6.3.1 the reference's Type.
          expect(references).toStrictEqual([
            {
              digest,
              transforms: [
                "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
              ],
              type: null,
              uri: "#comprobante",
            },
            {
              digest,
              transforms: [],
              type: "http://uri.etsi.org/01903#SignedProperties",
              uri: `#${attribute(properties ?? null, "Id")}`,
            },
            {
              digest,
              transforms: [],
              type: null,
              uri: `#${attribute(keyInfo ?? null, "Id")}`,
            },
          ]);

          // The signature is the comprobante's last child.
          const root = new DOMParser().parseFromString(
            signed,
            "text/xml"
          ).documentElement;

          expect(root?.lastChild?.localName).toBe("Signature");
        },
        { testCases: 10 }
      );
    });

    it("names in its signed properties the certificate that signed, as the SRI checks and xml-crypto doesn't", () => {
      hegel.test(
        (tc) => {
          const p12 = drawCertificate(tc, { email: false });

          const signed = signXml(
            drawXml(tc),
            { p12, password: PASSWORD },
            { algorithm }
          );

          const der = Buffer.from(
            forge.asn1
              .toDer(forge.pki.certificateToAsn1(forgeCertificate(p12)))
              .getBytes(),
            "latin1"
          );

          // The certificate as Node reads it, not as the signer does.
          const certificate = new X509Certificate(der);
          const [certDigest] = elements(signed, XADES, "CertDigest");
          expect({
            digest: certDigest
              ?.getElementsByTagNameNS(DSIG, "DigestValue")
              .item(0)?.textContent,
            embedded: textOf(signed, "X509Certificate").replaceAll(/\s/gu, ""),
            // RFC 4514: the most specific name first, commas between.
            issuer: textOf(signed, "X509IssuerName"),
            serial: textOf(signed, "X509SerialNumber"),
          }).toStrictEqual({
            digest: createHash(algorithm).update(der).digest("base64"),
            embedded: der.toString("base64"),
            issuer: certificate.issuer.split("\n").toReversed().join(","),
            // Node writes the serial as its hex digits, without leading zeros.
            serial: BigInt(`0x${certificate.serialNumber}`).toString(),
          });
        },
        { testCases: 10 }
      );
    });
  });

  it("is valid against XMLDSig's schema and XAdES 1.3.2's", async () => {
    await hegel.testAsync(
      async (tc) => {
        const signed = signXml(
          drawXml(tc),
          { p12: drawCertificate(tc), password: PASSWORD },
          { algorithm: drawAlgorithm(tc) }
        );

        await expect(xadesErrors(signatureOf(signed))).resolves.toStrictEqual(
          []
        );
      },
      { testCases: 10 }
    );
  });

  it("carries its certificate's public key as the key value, and addresses its XAdES properties to itself", () => {
    hegel.test(
      (tc) => {
        const p12 = drawCertificate(tc);
        const signed = signXml(drawXml(tc), { p12, password: PASSWORD });

        // The key as Node reads it from the certificate. A JWK's n and e are
        // the integers' big-endian bytes without leading zeros (RFC 7518,
        // section 6.3.1), which is XMLDSig's CryptoBinary (section 4.0.1).
        const jwk = new X509Certificate(
          forge.pki.certificateToPem(forgeCertificate(p12))
        ).publicKey.export({ format: "jwk" });

        const base64Url = (localName: string) =>
          Buffer.from(textOf(signed, localName), "base64").toString(
            "base64url"
          );

        expect({
          e: base64Url("Exponent"),
          n: base64Url("Modulus"),
        }).toStrictEqual({ e: jwk.e, n: jwk.n });
        // XAdES 1.3.2, section 6.2: Target refers to the signature the
        // properties qualify.
        const [signature] = elements(signed, DSIG, "Signature");
        const [qualifying] = elements(signed, XADES, "QualifyingProperties");
        expect(attribute(qualifying ?? null, "Target")).toBe(
          `#${attribute(signature ?? null, "Id")}`
        );
      },
      { testCases: 10 }
    );
  });

  it("stops verifying when any letter or digit of the document's text changes", () => {
    hegel.test(
      (tc) => {
        const signed = signXml(
          drawXml(tc),
          { p12: drawCertificate(tc), password: PASSWORD },
          { algorithm: drawAlgorithm(tc) }
        );

        const positions = textPositions(signed);
        tc.assume(positions.length > 0);
        const index = tc.draw(gs.sampledFrom(positions));

        // Another letter or digit: any shift but a whole turn.
        const shift = tc.draw(
          gs.integers({ maxValue: ALPHANUMERIC.length - 1, minValue: 1 })
        );

        const replacement = ALPHANUMERIC.charAt(
          (ALPHANUMERIC.indexOf(signed.charAt(index)) + shift) %
            ALPHANUMERIC.length
        );

        const tampered = `${signed.slice(0, index)}${replacement}${signed.slice(index + 1)}`;
        expect(() => verifySignature(tampered)).toThrow(SignatureError);
      },
      { testCases: 30 }
    );
  });

  it("stops verifying when its signed properties change", () => {
    hegel.test(
      (tc) => {
        const signed = signXml(
          drawXml(tc),
          { p12: drawCertificate(tc), password: PASSWORD },
          { algorithm: drawAlgorithm(tc) }
        );

        const time = textOf(signed, "SigningTime");

        const later = new Date(
          new Date(time).getTime() +
            tc.draw(gs.integers({ maxValue: 10 ** 9, minValue: 1 }))
        ).toISOString();

        const tampered = signed.replace(
          `<xades:SigningTime>${time}<`,
          `<xades:SigningTime>${later}<`
        );

        expect(tampered).not.toBe(signed);
        expect(() => verifySignature(tampered)).toThrow(SignatureError);
      },
      { testCases: 10 }
    );
  });

  it("stops verifying when another certificate is put in its place", () => {
    hegel.test(
      (tc) => {
        const xml = drawXml(tc);
        const algorithm = drawAlgorithm(tc);

        // Two key pairs, so the other certificate is really another.
        const signed = signXml(
          xml,
          { p12: drawCertificate(tc, { slot: 0 }), password: PASSWORD },
          { algorithm }
        );

        const other = signXml(
          xml,
          { p12: drawCertificate(tc, { slot: 1 }), password: PASSWORD },
          { algorithm }
        );

        const swapped = signed.replace(
          textOf(signed, "X509Certificate"),
          textOf(other, "X509Certificate")
        );

        expect(swapped).not.toBe(signed);
        expect(() => verifySignature(swapped)).toThrow(SignatureError);
      },
      { testCases: 10 }
    );
  });
});

describe("the issuer's name", () => {
  it("is written last RDN first, escaped as RFC 4514 and XML say, with E as EMAILADDRESS", async () => {
    const p12 = buildSelfSigned({
      commonName: "HOLDER",
      issuer: [
        { name: "countryName", value: "EC" },
        { name: "organizationName", value: "ACME, S.A. & HIJOS" },
        { name: "commonName", value: "CA <1>" },
        { name: "emailAddress", value: "ca@example.com" },
      ],
      keys: testKeys(0),
      password: PASSWORD,
    });

    const signed = signXml(comprobante("factura"), { p12, password: PASSWORD });
    expect(textOf(signed, "X509IssuerName")).toBe(
      String.raw`EMAILADDRESS=ca@example.com,CN=CA \<1\>,O=ACME\, S.A. & HIJOS,C=EC`
    );
    expect(() => verifySignature(signed)).not.toThrow();
    await expect(
      xsdErrors(signed, COMPROBANTES.factura)
    ).resolves.toStrictEqual([]);
  });
});

describe("what can't be signed", () => {
  const certificate = {
    p12: buildSelfSigned({
      commonName: "HOLDER",
      keys: testKeys(0),
      password: PASSWORD,
    }),
    password: PASSWORD,
  };

  const refusal = (xml: string) => {
    try {
      signXml(xml, certificate);
    } catch (error) {
      return error instanceof DocumentError ? error.reason : error;
    }

    return null;
  };

  it.each([
    [
      "a document whose root isn't the comprobante",
      '<factura id="otro"><a>1</a></factura>',
      "root_id",
    ],
    [
      "a document that goes on after its root, where the signature's place can't be told",
      '<factura id="comprobante"><a>1</a></factura><!-- </factura> -->',
      "trailing_content",
    ],
    [
      "a document with a stray character after its root's end tag",
      '<factura id="comprobante"><a>1</a></factura>!',
      "trailing_content",
    ],
    [
      "a document whose root declares a namespace its signature would inherit",
      '<factura id="comprobante" xmlns="urn:x"><a>1</a></factura>',
      "root_namespaces",
    ],
    [
      "a document with a DOCTYPE, whose entities would be signed as text",
      '<!DOCTYPE factura [<!ENTITY a "1">]><factura id="comprobante"><a>&a;</a></factura>',
      "doctype",
    ],
    [
      "a document that isn't well-formed",
      '<factura id="comprobante"><a>1</factura>',
      "malformed",
    ],
  ])("%s", (_, xml, reason) => {
    expect(refusal(xml)).toBe(reason);
  });

  it("a document that already carries a signature, which a second one would leave stale", () => {
    const signed = signXml(
      '<factura id="comprobante"><a>1</a></factura>',
      certificate
    );

    expect(refusal(signed)).toBe("already_signed");
  });
});
