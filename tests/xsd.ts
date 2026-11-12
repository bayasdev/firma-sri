import { readFile } from "node:fs/promises";
import { validateXML } from "xmllint-wasm";

const DS = "http://www.w3.org/2000/09/xmldsig#";
const XSD_DIR = new URL("data/xsd/", import.meta.url);

const xsdFile = async (fileName: string) => ({
  contents: await readFile(new URL(fileName, XSD_DIR), "utf-8"),
  fileName,
});

const preloaded = async (fileNames: string[]) =>
  await Promise.all(fileNames.map(xsdFile));

/** libxml2's complaints about a comprobante against the SRI's XSD for it. */
export const xsdErrors = async (xml: string, xsd: string) => {
  const result = await validateXML({
    preload: await preloaded([
      "xmldsig-core-schema.xsd",
      "XMLSchema.dtd",
      "datatypes.dtd",
    ]),
    schema: [await xsdFile(xsd)],
    xml: [{ contents: xml, fileName: "document.xml" }],
  });

  return result.errors.map((error) => error.message);
};

// XAdES.xsd imports XMLDSig from the W3C's URL; importing the local copy
// first makes libxml2 skip that one, with a warning.
const XADES_ENTRY = `<xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema"><xsd:import namespace="${DS}" schemaLocation="xmldsig-core-schema.xsd"/><xsd:import namespace="http://uri.etsi.org/01903/v1.3.2#" schemaLocation="XAdES.xsd"/></xsd:schema>`;

/** libxml2's complaints about a signature against XMLDSig and XAdES 1.3.2. */
export const xadesErrors = async (signature: string) => {
  const result = await validateXML({
    preload: await preloaded([
      "XAdES.xsd",
      "xmldsig-core-schema.xsd",
      "XMLSchema.dtd",
      "datatypes.dtd",
    ]),
    schema: [{ contents: XADES_ENTRY, fileName: "entry.xsd" }],
    xml: [{ contents: signature, fileName: "signature.xml" }],
  });

  return result.errors
    .map((error) => error.message)
    .filter((message) => !message.includes("parser warning"));
};
