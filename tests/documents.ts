import { readFileSync } from "node:fs";
import type * as hegel from "@hegeldev/hegel";
import * as gs from "@hegeldev/hegel/generators";

/**
 * One comprobante of each kind the SRI takes, with the XSD the SRI publishes
 * for it. The documents are made up: their issuer is the RUC of the ficha
 * técnica's own factura example.
 */
export const COMPROBANTES = {
  comprobanteRetencion: "ComprobanteRetencion_V2.0.0.xsd",
  factura: "factura_V2.1.0.xsd",
  guiaRemision: "GuiaRemision_V1.1.0.xsd",
  liquidacionCompra: "LiquidacionCompra_V1.1.0.xsd",
  notaCredito: "NotaCredito_V1.1.0.xsd",
  notaDebito: "NotaDebito_V1.0.0.xsd",
} as const;

export type Comprobante = keyof typeof COMPROBANTES;

export const comprobantes: Comprobante[] = [
  "factura",
  "liquidacionCompra",
  "notaCredito",
  "notaDebito",
  "guiaRemision",
  "comprobanteRetencion",
];

/** The unsigned XML of a kind's example. */
export const comprobante = (type: Comprobante) =>
  readFileSync(
    new URL(`data/comprobantes/${type}.xml`, import.meta.url),
    "utf-8"
  );

const LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

// Text as a comprobante carries it, with what XML and Canonical XML treat
// specially: markup characters, quotes, accents, tabs and line ends.
const TEXT = `${LETTERS}0123456789 .,-_/áéíóúñÑü&<>"'\t\n`;

const escapeText = (value: string) =>
  value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");

const escapeAttribute = (value: string) =>
  escapeText(value)
    .replaceAll('"', "&quot;")
    .replaceAll("\t", "&#x9;")
    .replaceAll("\n", "&#xA;");

// Names starting with "xml" are reserved (XML 1.0, section 2.3), and `xmlns`
// would declare a namespace.
const drawName = (tc: hegel.TestCase) =>
  tc
    .draw(gs.text({ alphabet: LETTERS, maxSize: 8, minSize: 1 }))
    .replace(/^xml/iu, "x");

const drawText = (tc: hegel.TestCase) =>
  tc.draw(gs.text({ alphabet: TEXT, maxSize: 20 }));

/** Attributes in the order drawn, which Canonical XML sorts. */
const drawAttributes = (tc: hegel.TestCase) => {
  const names = new Set(
    Array.from(
      { length: tc.draw(gs.integers({ maxValue: 3, minValue: 0 })) },
      () => drawName(tc)
    )
  );

  // The root's own id is the one the signature references.
  names.delete("id");

  return [...names]
    .map((name) => ` ${name}="${escapeAttribute(drawText(tc))}"`)
    .join("");
};

/**
 * An element with what it may hold, drawn: text, comments, CDATA sections,
 * empty elements and, down to `depth`, elements like itself.
 */
const drawElement = (
  tc: hegel.TestCase,
  depth: number,
  attributes: string
): string => {
  const content = () => {
    const kind = tc.draw(
      gs.integers({ maxValue: depth > 0 ? 4 : 3, minValue: 0 })
    );

    if (kind === 0) {
      return escapeText(drawText(tc));
    }

    if (kind === 1) {
      return `<!-- ${tc.draw(gs.text({ alphabet: LETTERS, maxSize: 10 }))} -->`;
    }

    if (kind === 2) {
      return `<![CDATA[${drawText(tc)}]]>`;
    }

    if (kind === 3) {
      return `<${drawName(tc)}${drawAttributes(tc)}/>`;
    }

    return drawElement(tc, depth - 1, "");
  };

  const name = drawName(tc);

  const contents = Array.from(
    { length: tc.draw(gs.integers({ maxValue: 4, minValue: 0 })) },
    content
  ).join("");

  return `<${name}${attributes}${drawAttributes(tc)}>${contents}</${name}>`;
};

/**
 * Any well-formed document a signer may be handed: a root with
 * `id="comprobante"` over drawn elements, attributes, text, comments and
 * CDATA sections, with or without an XML declaration and a last line end.
 */
export const drawXml = (tc: hegel.TestCase) =>
  `${tc.draw(gs.booleans()) ? '<?xml version="1.0" encoding="UTF-8"?>\n' : ""}${drawElement(tc, 3, ' id="comprobante"')}${tc.draw(gs.booleans()) ? "\n" : ""}`;
