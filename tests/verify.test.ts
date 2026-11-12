import { beforeAll, describe, expect, it } from "vitest";
import { certificateHolds } from "../src/certificate.ts";
import { signXml } from "../src/sign.ts";
import { SignatureError, verifySignature } from "../src/verify.ts";
import { createCaStyleCertificate } from "./certificates.ts";
import { comprobante } from "./documents.ts";

const nested = (depth: number) =>
  `${"<a>".repeat(depth)}${"</a>".repeat(depth)}`;

// The issuer of the ficha técnica's own factura example, and of ours.
const RUC = "1792146739001";
const PASSWORD = "clave";

/** How far the signing time may sit from the moment `beforeAll` signed. */
const SIGNING_TOLERANCE_MS = 5000;
const SIGNATURE = /<ds:Signature[\s\S]*<\/ds:Signature>/u;

describe(verifySignature, () => {
  let signed: string;
  let signedAt: Date;

  beforeAll(() => {
    const p12 = createCaStyleCertificate({
      ca: "security-data",
      password: PASSWORD,
      ruc: RUC,
    });

    signedAt = new Date();
    signed = signXml(comprobante("factura"), { p12, password: PASSWORD });
  });

  it("a document signed by the signer verifies, with its certificate and signing time", () => {
    const { certificate, signingTime } = verifySignature(signed);
    expect(certificate.holder).toStrictEqual({ ruc: RUC });
    expect(certificateHolds(certificate, RUC)).toBeTruthy();
    expect(certificateHolds(certificate, "1790012345001")).toBeFalsy();
    // SigningTime is when beforeAll signed it.
    expect(
      Math.abs((signingTime?.getTime() ?? 0) - signedAt.getTime())
    ).toBeLessThan(SIGNING_TOLERANCE_MS);
  });

  it("any change to the signed content breaks it", () => {
    const tampered = signed.replace("<importeTotal>", "<importeTotal>1");
    expect(tampered).not.toBe(signed);
    expect(() => verifySignature(tampered)).toThrow(SignatureError);
  });

  it("a changed buyer name breaks it too", () => {
    const tampered = signed.replace(
      "FERRETERÍA EL SOL S.A.",
      "FERRETERIA EL SOL S.A."
    );

    expect(() => verifySignature(tampered)).toThrow(SignatureError);
  });

  it("an unsigned document has no signature", () => {
    expect(() => verifySignature(comprobante("factura"))).toThrow(
      "one enveloped signature"
    );
  });

  it("a second signature, as in a wrapping attack, is refused", () => {
    const match: RegExpExecArray | null = SIGNATURE.exec(signed);
    const signature = match ? match[0] : "";

    const doubled = signed.replace(
      "</factura>",
      `<extra>${signature}</extra></factura>`
    );

    expect(() => verifySignature(doubled)).toThrow(SignatureError);
  });

  it("a signature over another element doesn't vouch for the document", () => {
    // Same signature, but the root no longer has the id it references.
    const renamed = signed.replace('id="comprobante"', 'id="otro"');
    expect(() => verifySignature(renamed)).toThrow(SignatureError);
  });

  it("malformed XML is refused", () => {
    expect(() => verifySignature("<factura><")).toThrow(SignatureError);
  });

  it("a document nested far past any legitimate one is refused as a signature error, not a stack overflow", () => {
    // Regression: the tree walks after the parse threw a RangeError.
    const deep = `<factura id="comprobante">${nested(200_000)}</factura>`;
    expect(() => verifySignature(deep)).toThrow(SignatureError);
  });

  it("a signed document that declares a DOCTYPE is refused", () => {
    // The signature covers the root, not the prologue, so only a guard here stops a DTD.
    const declared = signed.replace(
      /^(?<declaration><\?xml[^>]*\?>)?/u,
      "$<declaration><!DOCTYPE factura>"
    );

    expect(declared).toContain("<!DOCTYPE");
    expect(() => verifySignature(declared)).toThrow(
      "The XML declares a DOCTYPE"
    );
  });
});
