import * as hegel from "@hegeldev/hegel";
import * as gs from "@hegeldev/hegel/generators";
import forge from "node-forge";
import { describe, expect, it } from "vitest";
import { certificateHolds, readCertificate } from "../src/certificate.ts";
import type { CertificateInfo } from "../src/certificate.ts";
import {
  buildSelfSigned,
  positiveSerial,
  textExtension,
} from "../src/self-signed.ts";
import { createSelfSignedCertificate } from "../src/testing.ts";
import {
  createCaStyleCertificate,
  subjectAltName,
  testKeys,
} from "./certificates.ts";

const now = new Date("2026-09-29T12:00:00Z");

/** A certificate that identifies this holder. */
const info = (holder: CertificateInfo["holder"]): CertificateInfo => ({
  canSign: true,
  holder,
  holderIdentification: null,
  holderName: null,
  issuer: "CN=CA",
  issuerName: null,
  kind: null,
  notAfter: now,
  notBefore: now,
  serialNumber: "01",
  subject: "CN=HOLDER",
});

describe("certificates", () => {
  const p12 = createSelfSignedCertificate({
    commonName: "ANDINA COMERCIAL S.A.",
    now,
    password: "s3cret",
    validDays: 730,
  });

  it("a created certificate reads back with its holder and validity", () => {
    expect(readCertificate(p12, "s3cret")).toMatchObject({
      issuer: "CN=ANDINA COMERCIAL S.A.",
      notAfter: new Date("2028-09-28T12:00:00Z"),
      notBefore: now,
      subject: "CN=ANDINA COMERCIAL S.A.",
    });
  });

  it("a certificate serial is positive, as RFC 5280 asks: DER reads a first byte of 0x80 or more as negative", () => {
    hegel.test((tc) => {
      const bytes = tc.draw(gs.binary({ maxSize: 20, minSize: 1 }));
      const serial = positiveSerial(bytes);
      const hex = Buffer.from(bytes).toString("hex");
      expect([
        Number.parseInt(serial.slice(0, 2), 16) < 0x80,
        serial.slice(2),
        Number.parseInt(serial.slice(0, 2), 16) % 0x80,
      ]).toStrictEqual([
        true,
        hex.slice(2),
        Number.parseInt(hex.slice(0, 2), 16) % 0x80,
      ]);
    });
  });

  it("a legacy 3DES-encrypted file, as some CAs issue, can be read", () => {
    const keys = forge.pki.rsa.generateKeyPair({ bits: 1024 });
    const certificate = forge.pki.createCertificate();
    certificate.publicKey = keys.publicKey;
    certificate.serialNumber = "01";
    certificate.validity.notBefore = now;
    certificate.validity.notAfter = now;
    certificate.setSubject([{ name: "commonName", value: "LEGACY" }]);
    certificate.setIssuer([{ name: "commonName", value: "LEGACY CA" }]);
    certificate.sign(keys.privateKey, forge.md.sha256.create());

    const der = forge.asn1
      .toDer(
        forge.pkcs12.toPkcs12Asn1(keys.privateKey, [certificate], "old", {
          algorithm: "3des",
        })
      )
      .getBytes();

    expect(
      readCertificate(forge.util.binary.raw.decode(der), "old")
    ).toMatchObject({ issuer: "CN=LEGACY CA", subject: "CN=LEGACY" });
  });

  it("a wrong password is refused", () => {
    expect(() => readCertificate(p12, "wrong")).toThrow(
      expect.objectContaining({ reason: "wrong_password" })
    );
  });

  it("a file that isn't PKCS#12 is refused", () => {
    expect(() =>
      readCertificate(new TextEncoder().encode("not a certificate"), "")
    ).toThrow(expect.objectContaining({ reason: "not_pkcs12" }));
  });
});

describe("certificate holder", () => {
  it.each([
    ["Security Data (private extensions)", "security-data"],
    ["Uanataca (Subject Alternative Name)", "uanataca"],
  ] as const)("reads the RUC and cédula of a %s certificate", (_, ca) => {
    const p12 = createCaStyleCertificate({
      ca,
      cedula: "1710034065",
      password: "x",
      ruc: "1792146739001",
    });

    expect(readCertificate(p12, "x").holder).toStrictEqual({
      cedula: "1710034065",
      ruc: "1792146739001",
    });
  });

  it("a certificate created for a holder reads back with its RUC and cédula", () => {
    const created = createSelfSignedCertificate({
      cedula: "1710034065",
      password: "x",
      ruc: "1710034065001",
    });

    const read = readCertificate(created, "x");
    expect(read.holder).toStrictEqual({
      cedula: "1710034065",
      ruc: "1710034065001",
    });
    expect(certificateHolds(read, "1710034065001")).toBeTruthy();
  });

  it("a certificate without CA fields has no known holder", () => {
    const p12 = createSelfSignedCertificate({ commonName: "X", password: "x" });
    expect(readCertificate(p12, "x").holder).toStrictEqual({});
  });

  it.each([
    ["its RUC", { ruc: "1792146739001" }, "1792146739001", true],
    ["another RUC", { ruc: "1790012345001" }, "1792146739001", false],
    [
      "a natural person's cédula plus 001",
      { cedula: "1710034065" },
      "1710034065001",
      true,
    ],
    [
      "a cédula that isn't the RUC's",
      { cedula: "1710034065" },
      "1792146739001",
      false,
    ],
    ["nothing", {}, "1792146739001", false],
  ])("a certificate with %s holds that RUC: %s", (_, holder, ruc, expected) => {
    expect(certificateHolds(info(holder), ruc)).toBe(expected);
  });
});

/** keyUsage's DER value: a BIT STRING, digital signature its first bit. */
const keyUsage = (bits: number, unused: number) => ({
  id: "2.5.29.15",
  value: String.fromCodePoint(0x03, 0x02, unused, bits),
});

// The SRI's offline invoicing tool signs only with a key whose usage allows
// it, and reads the RUC from the CA's extension over any otherName.
describe("what the SRI's offline tool asks of a certificate", () => {
  it.each([
    ["no keyUsage, which restricts nothing (RFC 5280, 4.2.1.3)", [], true],
    ["keyUsage with digital signature", [keyUsage(0x80, 7)], true],
    ["keyUsage with key encipherment only", [keyUsage(0x20, 5)], false],
  ] as const)("can sign with %s: %s", (_, extensions, expected) => {
    const p12 = buildSelfSigned({
      commonName: "X",
      extensions: [...extensions],
      keys: testKeys(),
      password: "x",
    });

    expect(readCertificate(p12, "x").canSign).toBe(expected);
  });

  it("reads the RUC from the CA's extension even when an otherName after it says another", () => {
    const oid = "1.3.6.1.4.1.47286.102.3.11";

    const p12 = buildSelfSigned({
      commonName: "X",
      extensions: [
        textExtension(oid, "1792146739001"),
        subjectAltName([[oid, "1790012345001"]]),
      ],
      keys: testKeys(),
      password: "x",
    });

    expect(readCertificate(p12, "x").holder.ruc).toBe("1792146739001");
  });
});
