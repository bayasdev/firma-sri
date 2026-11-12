import * as hegel from "@hegeldev/hegel";
import * as gs from "@hegeldev/hegel/generators";
import type forge from "node-forge";
import { describe, expect, it } from "vitest";
import {
  formatDistinguishedName,
  holderName,
  identifyHolder,
  issuerName,
  normalizeOrganization,
  serialIdentification,
} from "../src/certificate-names.ts";

type Attribute = forge.pki.CertificateField;

const CN = "2.5.4.3";
const SERIAL = "2.5.4.5";
const O = "2.5.4.10";
const OU = "2.5.4.11";
const C = "2.5.4.6";

const SHORT_NAMES = new Map([
  [CN, "CN"],
  [SERIAL, "serialNumber"],
  [O, "O"],
  [C, "C"],
]);

const attribute = (type: string, value: string): Attribute => ({
  shortName: SHORT_NAMES.get(type) ?? "OU",
  type,
  value,
});

/** Reads an RFC 4514 string back: an independent reader of what we write. */
const parseDistinguishedName = (dn: string) => {
  const pairs: [string, string][] = [];
  let current = "";
  let escaped = false;

  const finish = () => {
    const at = current.indexOf("=");
    pairs.push([current.slice(0, at), current.slice(at + 1)]);
    current = "";
  };

  for (let i = 0; i < dn.length; i += 1) {
    const character = dn.charAt(i);

    if (escaped) {
      current += character;
      escaped = false;
    } else if (character === "\\") {
      escaped = true;
    } else if (character === ",") {
      finish();
      // The space after the separator.
      i += 1;
    } else {
      current += character;
    }
  }

  finish();

  return pairs;
};

const digits = (size: number) =>
  gs.text({ alphabet: "0123456789", maxSize: size, minSize: size });

const words = gs.text({ maxSize: 24, minSize: 0 });

describe("distinguished names", () => {
  it("the printed name of the certificate in the owner's console", () => {
    expect(
      formatDistinguishedName([
        attribute(CN, "MARIA ELENA PEREZ LOPEZ"),
        attribute(SERIAL, "1710034065-200224172048"),
        attribute(O, "SECURITY DATA S.A. 2"),
        attribute(C, "EC"),
      ])
    ).toBe(
      "CN=MARIA ELENA PEREZ LOPEZ, serialNumber=1710034065-200224172048, O=SECURITY DATA S.A. 2, C=EC"
    );
  });

  it("escapes a comma inside a value", () => {
    expect(
      formatDistinguishedName([attribute(O, "ACME, S.A."), attribute(C, "EC")])
    ).toBe(String.raw`O=ACME\, S.A., C=EC`);
  });

  it("whatever the values hold, reading the name back gives them", () => {
    hegel.test(
      (tc) => {
        const attributes = tc.draw(
          gs.arrays(gs.tuples(gs.sampledFrom([CN, O, OU, SERIAL]), words), {
            maxSize: 6,
            minSize: 1,
          })
        );

        const dn = formatDistinguishedName(
          attributes.map(([type, value]) => attribute(type, value))
        );

        expect(
          parseDistinguishedName(dn).map(([, value]) => value)
        ).toStrictEqual(attributes.map(([, value]) => value.trim()));
      },
      { testCases: 300 }
    );
  });
});

describe("the holder's name", () => {
  it("is the common name wherever it sits among the attributes", () => {
    hegel.test(
      (tc) => {
        const others = tc.draw(
          gs.arrays(gs.tuples(gs.sampledFrom([O, OU, SERIAL, C]), words), {
            maxSize: 5,
          })
        );

        const name = tc.draw(gs.text({ maxSize: 30, minSize: 1 }));

        const at = tc.draw(
          gs.integers({ maxValue: others.length, minValue: 0 })
        );

        const attributes = others.map(([type, value]) =>
          attribute(type, value)
        );

        attributes.splice(at, 0, attribute(CN, name));
        expect(holderName(attributes)).toBe(
          name.trim() === "" ? undefined : name.trim()
        );
      },
      { testCases: 200 }
    );
  });

  it("is missing when there is no common name", () => {
    expect(
      holderName([attribute(O, "ACME"), attribute(C, "EC")])
    ).toBeUndefined();
  });
});

describe("the holder's identification", () => {
  it("reads a cédula before the dash of the serial number, as Security Data writes it", () => {
    hegel.test(
      (tc) => {
        const cedula = tc.draw(digits(10));
        const rest = tc.draw(digits(12));
        expect(
          serialIdentification([attribute(SERIAL, `${cedula}-${rest}`)])
        ).toStrictEqual({ cedula });
      },
      { testCases: 100 }
    );
  });

  it("skips a document-type prefix, and tells a RUC from a cédula by its length", () => {
    hegel.test(
      (tc) => {
        const prefix = tc.draw(
          gs.sampledFrom(["", "IDCEC-", "PNOEC-", "NTREC-"])
        );

        const ruc = tc.draw(digits(13));
        expect(
          serialIdentification([attribute(SERIAL, `${prefix}${ruc}`)])
        ).toStrictEqual({ ruc });
      },
      { testCases: 100 }
    );
  });

  it("finds nothing in what isn't a cédula or a RUC", () => {
    hegel.test(
      (tc) => {
        const serial = tc.draw(
          gs.oneOf(
            digits(9),
            digits(11),
            digits(12),
            digits(14),
            gs.text({ alphabet: "abcXYZ-", maxSize: 12, minSize: 0 })
          )
        );

        expect(serialIdentification([attribute(SERIAL, serial)])).toStrictEqual(
          {}
        );
      },
      { testCases: 100 }
    );
    expect(serialIdentification([attribute(CN, "SIN SERIAL")])).toStrictEqual(
      {}
    );
  });

  it("a person's own RUC is a natural person; another RUC, a representative", () => {
    hegel.test(
      (tc) => {
        const cedula = tc.draw(digits(10));
        const other = tc.draw(digits(13));
        expect(identifyHolder({ cedula })).toStrictEqual({
          identification: cedula,
          kind: "natural_person",
        });
        expect(identifyHolder({ cedula, ruc: `${cedula}001` }).kind).toBe(
          "natural_person"
        );
        expect(identifyHolder({ cedula, ruc: other })).toStrictEqual({
          identification: cedula,
          kind:
            other === `${cedula}001`
              ? "natural_person"
              : "legal_representative",
        });
      },
      { testCases: 200 }
    );
  });

  it("with only a RUC, names it but can't say what the holder is", () => {
    expect(identifyHolder({ ruc: "1792146739001" })).toStrictEqual({
      identification: "1792146739001",
      kind: null,
    });
    expect(identifyHolder({})).toStrictEqual({
      identification: null,
      kind: null,
    });
  });
});

describe("the issuer's name", () => {
  it.each([
    ["SECURITY DATA S.A. 2", "Security Data"],
    ["BANCO CENTRAL DEL ECUADOR", "Banco Central del Ecuador"],
    ["ANF AC", "ANF AC"],
    ["UANATACA ECUADOR S.A.", "Uanataca Ecuador"],
    ["Consejo de la Judicatura", "Consejo de la Judicatura"],
    ["ARGOS DATA CIA. LTDA.", "Argos Data"],
  ])("%s is called %s", (written, name) => {
    expect(normalizeOrganization(written)).toBe(name);
  });

  it("does not depend on the legal form written after the name", () => {
    hegel.test(
      (tc) => {
        const name = tc.draw(
          gs.fromRegex("[A-Z]{4,9}( [A-Z]{4,9}){0,2}", { fullmatch: true })
        );

        const suffix = tc.draw(
          gs.sampledFrom(["", " S.A.", " S.A. 2", " CIA. LTDA.", " SAS", " 3"])
        );

        expect(normalizeOrganization(`${name}${suffix}`)).toBe(
          normalizeOrganization(name)
        );
      },
      { testCases: 200 }
    );
  });

  it("is the same name when said again", () => {
    hegel.test(
      (tc) => {
        const name = tc.draw(
          gs.fromRegex("[A-Za-z]{2,9}( [A-Za-z]{2,9}){0,3}", {
            fullmatch: true,
          })
        );

        const once = normalizeOrganization(name);
        expect(normalizeOrganization(once)).toBe(once);
      },
      { testCases: 200 }
    );
  });

  it("is the organization, not the CA's long common name, in any order", () => {
    const issuer = [
      attribute(C, "EC"),
      attribute(O, "SECURITY DATA S.A. 2"),
      attribute(OU, "ENTIDAD DE CERTIFICACION DE INFORMACION"),
      attribute(CN, "AUTORIDAD DE CERTIFICACION SUBCA-2 SECURITY DATA"),
    ];

    expect(issuerName(issuer)).toBe("Security Data");
    expect(issuerName(issuer.toReversed())).toBe("Security Data");
  });

  it("falls back to the common name, and to nothing", () => {
    expect(issuerName([attribute(CN, "UANATACA ECUADOR CA")])).toBe(
      "Uanataca Ecuador CA"
    );
    expect(issuerName([attribute(C, "EC")])).toBeUndefined();
  });
});
