import forge from "node-forge";
import type { RawExtension } from "./certificate.ts";

/**
 * Random bytes as a certificate serial in hex. RFC 5280 wants a positive
 * serial, and DER reads a first byte of 0x80 or more as a negative integer,
 * so the first byte's top bit is cleared.
 */
export const positiveSerial = (bytes: Uint8Array) =>
  Array.from(bytes, (byte, index) =>
    (index === 0 ? byte % 0x80 : byte).toString(16).padStart(2, "0")
  ).join("");

/** Builds a self-signed certificate with its key as a PKCS#12 file. */
export const buildSelfSigned = ({
  commonName,
  password,
  validDays = 365,
  now = new Date(),
  extensions = [],
  subject = [{ name: "commonName", value: commonName }],
  issuer = subject,
  keys = forge.pki.rsa.generateKeyPair({ bits: 2048 }),
}: {
  commonName: string;
  password: string;
  validDays?: number;
  now?: Date;
  extensions?: RawExtension[];
  /** The subject's attributes, most specific first; the common name alone by default. */
  subject?: { name: string; value: string }[];
  /** The issuer's attributes; the subject's by default (self-signed). */
  issuer?: { name: string; value: string }[];
  /**
   * The RSA-2048 key pair to certify; a fresh one by default. Generating
   * keys is what makes a certificate slow, so tests that build many pass the
   * same pair.
   */
  keys?: forge.pki.rsa.KeyPair;
}): Uint8Array => {
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = positiveSerial(
    forge.util.binary.raw.decode(forge.random.getBytesSync(16))
  );
  certificate.validity.notBefore = now;
  certificate.validity.notAfter = new Date(
    now.getTime() + validDays * 86_400_000
  );
  certificate.setSubject(subject);
  certificate.setIssuer(issuer);
  certificate.setExtensions(extensions);
  certificate.sign(keys.privateKey, forge.md.sha256.create());

  const asn1 = forge.pkcs12.toPkcs12Asn1(
    keys.privateKey,
    [certificate],
    password,
    {
      algorithm: "aes256",
    }
  );

  return forge.util.binary.raw.decode(forge.asn1.toDer(asn1).getBytes());
};

/** A private extension whose value is a UTF8String, as most CAs write the holder's cédula and RUC. */
export const textExtension = (oid: string, text: string): RawExtension => ({
  id: oid,
  value: forge.asn1
    .toDer(
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.UTF8,
        false,
        forge.util.encodeUtf8(text)
      )
    )
    .getBytes(),
});

// Security Data's arc, where it records the holder's cédula (.3.1) and RUC
// (.3.11).
const SECURITY_DATA = "1.3.6.1.4.1.37746";

/**
 * A throwaway self-signed certificate as a PKCS#12 file, to try the signer
 * and to test code that signs. It has no legal value and the SRI rejects it.
 *
 * With `ruc` or `cedula` it identifies that holder where Security Data
 * records them, so `readCertificate` and `certificateHolds` read them back.
 */
export const createSelfSignedCertificate = ({
  ruc,
  cedula,
  commonName = ruc ?? cedula ?? "CERTIFICADO DE PRUEBA",
  ...options
}: {
  commonName?: string;
  password: string;
  ruc?: string;
  cedula?: string;
  /** How long it's valid from `now`; a year by default. */
  validDays?: number;
  now?: Date;
}) =>
  buildSelfSigned({
    ...options,
    commonName,
    extensions: [
      ...(cedula === undefined
        ? []
        : [textExtension(`${SECURITY_DATA}.3.1`, cedula)]),
      ...(ruc === undefined
        ? []
        : [textExtension(`${SECURITY_DATA}.3.11`, ruc)]),
    ],
  });
