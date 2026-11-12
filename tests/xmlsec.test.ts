import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import * as hegel from "@hegeldev/hegel";
import * as gs from "@hegeldev/hegel/generators";
import { DOMParser } from "@xmldom/xmldom";
import { afterAll, describe, expect, it } from "vitest";
import { buildSelfSigned } from "../src/self-signed.ts";
import { signXml } from "../src/sign.ts";
import type { SignatureAlgorithm } from "../src/sign.ts";
import { testKeys } from "./certificates.ts";
import { comprobante, comprobantes, drawXml } from "./documents.ts";

const DSIG = "http://www.w3.org/2000/09/xmldsig#";
const XADES = "http://uri.etsi.org/01903/v1.3.2#";
const algorithms: SignatureAlgorithm[] = ["sha1", "sha256"];

// Every machine that has xmlsec1 runs these, and CI must have it.
const installed = spawnSync("xmlsec1", ["--version"]).status === 0;

if (!installed && process.env.CI !== undefined) {
  throw new Error("CI needs xmlsec1 to check the signatures against it");
}

const directory = mkdtempSync(path.join(tmpdir(), "firma-sri-"));

const certificate = () => ({
  p12: buildSelfSigned({
    commonName: "HOLDER",
    keys: testKeys(0),
    password: "clave",
  }),
  password: "clave",
});

/**
 * Whether xmlsec1 (libxml2's Canonical XML and OpenSSL's hashes and RSA)
 * verifies the document's signature with the key of the certificate it
 * embeds. `--insecure` leaves out only the certificate's chain, which a
 * throwaway certificate doesn't have.
 */
const xmlsecVerifies = (signed: string) => {
  const root =
    new DOMParser().parseFromString(signed, "text/xml").documentElement
      ?.tagName ?? "";

  const file = path.join(directory, "signed.xml");
  writeFileSync(file, signed);

  // The schemas aren't loaded, so xmlsec1 is told which attributes are IDs.
  const { status } = spawnSync("xmlsec1", [
    "--verify",
    "--insecure",
    "--id-attr:id",
    root,
    "--id-attr:Id",
    `${DSIG}:KeyInfo`,
    "--id-attr:Id",
    `${XADES}:SignedProperties`,
    file,
  ]);

  // It exits with 0 only when every reference and the signature verify.
  return status === 0;
};

describe.skipIf(!installed)("a signed document, read by xmlsec1", () => {
  afterAll(() => {
    rmSync(directory, { recursive: true });
  });

  it.each(algorithms)(
    "verifies, whatever the document, with %s",
    (algorithm) => {
      hegel.test(
        (tc) => {
          const signed = signXml(drawXml(tc), certificate(), { algorithm });
          expect(xmlsecVerifies(signed)).toBeTruthy();
        },
        { testCases: 25 }
      );
    }
  );

  it("verifies for each kind of comprobante", () => {
    hegel.test(
      (tc) => {
        const signed = signXml(
          comprobante(tc.draw(gs.sampledFrom(comprobantes))),
          certificate(),
          { algorithm: tc.draw(gs.sampledFrom(algorithms)) }
        );

        expect(xmlsecVerifies(signed)).toBeTruthy();
      },
      { testCases: 12 }
    );
  });

  it("stops verifying when the document's text changes", () => {
    const signed = signXml(comprobante("factura"), certificate());
    const tampered = signed.replace("<importeTotal>", "<importeTotal>1");
    expect(tampered).not.toBe(signed);
    expect(xmlsecVerifies(tampered)).toBeFalsy();
  });
});
