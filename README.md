# firma-sri

Firma comprobantes electrónicos del SRI de Ecuador con un certificado `.p12`, y verifica la firma de los que recibes.

[![npm](https://img.shields.io/npm/v/firma-sri)](https://www.npmjs.com/package/firma-sri) [![Descargas](https://img.shields.io/npm/dm/firma-sri)](https://www.npmjs.com/package/firma-sri) [![CI](https://github.com/bayasdev/firma-sri/actions/workflows/ci.yml/badge.svg)](https://github.com/bayasdev/firma-sri/actions/workflows/ci.yml) [![Licencia](https://img.shields.io/npm/l/firma-sri)](https://github.com/bayasdev/firma-sri/blob/main/LICENSE)

```typescript
import { readFile } from "node:fs/promises";
import { signXml, verifySignature } from "firma-sri";

const p12 = await readFile("certificado.p12");
const firmado = signXml(xml, { p12, password: "clave del certificado" });

const { certificate, signingTime } = verifySignature(firmado);
certificate.holder; // { ruc: "1792146739001" }
```

- **Escrita desde las especificaciones.** La ficha técnica del SRI, XMLDSig, XAdES 1.3.2, Canonical XML 1.0 y RFC 4514, citadas junto al código.
- **Los seis comprobantes.** Factura, liquidación de compra, nota de crédito, nota de débito, guía de remisión y comprobante de retención. El SRI autorizó este perfil de firma en su ambiente de pruebas para los seis.
- **Firma y verifica.** Lee quién firmó un comprobante recibido y comprueba que nadie lo cambió después.
- **Lee el certificado.** El RUC y la cédula del titular, de las catorce entidades de certificación acreditadas en Ecuador, y los archivos antiguos con RC2 o 3DES.
- **No toca tu XML.** La firma se añade al final y cada carácter del documento queda como estaba.
- **Probada con propiedades.** Documentos generados al azar, verificados con xml-crypto y con xmlsec1, y validados contra los XSD del SRI y de XAdES.
- **Publicada con procedencia.** Cada versión sale de GitHub Actions con una declaración de procedencia de npm que puedes verificar.

## Instalación

```bash
pnpm add firma-sri
```

O con `npm install firma-sri`, `yarn add firma-sri` o `bun add firma-sri`.

Necesita Node.js 22.12 o posterior, porque firma con `node:crypto`. Se publica solo como módulo ES, y `require("firma-sri")` también lo carga. No funciona en el navegador.

## API

### Firmar

#### `signXml(xml: string, certificado: { p12: Uint8Array; password: string }, opciones?: { algorithm?: "sha1" | "sha256" }): string`

Devuelve el mismo XML con una firma XAdES-BES como último hijo de la raíz. La raíz debe llevar `id="comprobante"`, como piden los esquemas del SRI.

```typescript
const firmado = signXml(xml, { p12, password });
```

Firma con RSA-SHA1, que es lo que especifica la ficha técnica (sección 6.8). Con `{ algorithm: "sha256" }` firma con RSA-SHA256.

Lanza un `DocumentError` cuando no puede firmar el documento, con el motivo en `reason`.

| `reason` | Qué falla |
| --- | --- |
| `"malformed"` | El XML no está bien formado. |
| `"doctype"` | Declara un `DOCTYPE`, cuyas entidades se firmarían como texto que nadie escribió. |
| `"root_id"` | La raíz no lleva `id="comprobante"`. |
| `"root_namespaces"` | La raíz declara espacios de nombres, que la firma heredaría. |
| `"already_signed"` | Ya lleva una firma. |
| `"trailing_content"` | Hay algo después de la etiqueta de cierre de la raíz. |

Lanza un `CertificateError` cuando no puede abrir el archivo `.p12`.

| `reason` | Qué falla |
| --- | --- |
| `"not_pkcs12"` | El archivo no es un PKCS#12. |
| `"wrong_password"` | La clave no abre el archivo. |
| `"no_private_key"` | El archivo no trae una clave privada con su certificado. |

`signXml` firma con cualquier certificado que el archivo contenga. No mira si caducó ni si su clave puede firmar. Eso lo dice `readCertificate`.

### Verificar

#### `verifySignature(xml: string): { certificate: CertificateInfo; signingTime: Date | null }`

Comprueba la firma de un comprobante y devuelve el certificado que lo firmó y la hora de la firma. Exige una sola firma, hija de la raíz, que cubra el documento entero y sus propiedades XAdES.

```typescript
try {
  const { certificate } = verifySignature(xml);
  certificateHolds(certificate, "1792146739001"); // true si lo firmó ese RUC
} catch (error) {
  // SignatureError: sin firma, alterado, o la firma no cubre el documento
}
```

Dice quién firmó y que nada cambió desde entonces. No dice que el SRI haya autorizado el comprobante, ni que el certificado venga de una entidad acreditada.

### Leer un certificado

#### `readCertificate(p12: Uint8Array, password: string): CertificateInfo`

Abre un archivo `.p12` y dice de quién es, quién lo emitió y hasta cuándo vale. Sirve para revisar un certificado antes de guardarlo o de firmar con él.

```typescript
const certificado = readCertificate(p12, password);
certificado.holder; // { ruc: "1792146739001", cedula: "1710034065" }
certificado.issuerName; // "Security Data"
certificado.notAfter < new Date(); // true si ya caducó
certificado.canSign; // false si su clave no puede firmar
```

| Campo | Qué es |
| --- | --- |
| `holder` | El RUC y la cédula del titular, de los campos propios de cada entidad de certificación. |
| `holderName` | El nombre del titular. |
| `holderIdentification` | La cédula del titular, o su RUC si el certificado no trae cédula. |
| `kind` | `"natural_person"`, o `"legal_representative"` cuando el titular representa a una empresa. `null` si el certificado no lo dice. |
| `issuerName` | La entidad de certificación como se la nombra: `"Security Data"`. |
| `subject`, `issuer` | Los nombres completos, en el formato de RFC 4514. |
| `serialNumber` | El número de serie, en hexadecimal. |
| `notBefore`, `notAfter` | Desde y hasta cuándo vale. |
| `canSign` | Si su clave puede firmar (RFC 5280, sección 4.2.1.3). |

#### `certificateHolds(certificado: CertificateInfo, ruc: string): boolean`

Dice si el certificado identifica a ese RUC: por su campo de RUC o, en una persona natural, por su cédula seguida de `001`.

### Un certificado de prueba

#### `createSelfSignedCertificate(opciones): Uint8Array`

Crea un `.p12` autofirmado para probar tu código sin un certificado real. No tiene valor legal y el SRI lo rechaza. Se importa aparte, de `firma-sri/testing`.

```typescript
import { createSelfSignedCertificate } from "firma-sri/testing";

const p12 = createSelfSignedCertificate({
  ruc: "1792146739001",
  password: "clave",
});
```

Acepta `commonName`, `ruc`, `cedula`, `validDays` (365 por defecto) y `now`.

## Qué firma, exactamente

Una firma `ds:Signature` envuelta (enveloped), con XAdES-BES 1.3.2 y Canonical XML 1.0 inclusivo, como la escribe el facturador gratuito del SRI.

- `SignedInfo` lleva tres referencias: el documento (`#comprobante`, con la transformación `enveloped-signature`), las propiedades firmadas de XAdES y el `KeyInfo`.
- `KeyInfo` lleva el certificado del titular, sin su cadena, y su clave pública como `RSAKeyValue`.
- `SigningTime` es la hora de la firma en Ecuador continental, al segundo: `2026-10-02T07:51:22-05:00`. El SRI rechaza una firma con fecha posterior a la suya, así que el reloj de tu servidor debe estar sincronizado.
- `X509IssuerName` sigue RFC 4514, con `EMAILADDRESS` en lugar de `E`, porque el verificador del SRI lee el nombre con `X500Principal` de Java.
- `X509SerialNumber` es el número de serie en decimal.

## Qué no hace

- No arma el XML del comprobante ni calcula la clave de acceso.
- No envía el comprobante al SRI ni consulta su autorización.
- No comprueba la cadena del certificado ni si fue revocado.

## Contribuir

```bash
pnpm install
pnpm check        # formato, lint y código sin usar
pnpm check-types  # tipos
pnpm test         # pruebas
pnpm build        # compila a dist/
```

Las pruebas que verifican con [xmlsec1](https://www.aleksey.com/xmlsec/) corren si lo tienes instalado (`brew install xmlsec1`, `apt install xmlsec1`). CI siempre las corre.

Cada cambio llega a `main` con un pull request. Las reglas del repositorio están en [AGENTS.md](https://github.com/bayasdev/firma-sri/blob/main/AGENTS.md).

## In English

firma-sri signs the electronic documents (comprobantes electrónicos) of Ecuador's tax authority, the SRI, with a `.p12` certificate, and verifies the signature of the ones you receive. It writes the XAdES-BES signature the SRI's profile asks for, for all six document types.

```typescript
import { signXml, verifySignature } from "firma-sri";

const signed = signXml(xml, { p12, password });
const { certificate, signingTime } = verifySignature(signed);
```

It needs Node.js 22.12 or later. Function names, error reasons and messages are English. The API reference above applies as written.

## Licencia

[Apache 2.0](https://github.com/bayasdev/firma-sri/blob/main/LICENSE). Los esquemas con que se prueba (`tests/data/xsd`) son del [SRI](https://www.sri.gob.ec/facturacion-electronica), del [W3C](https://www.w3.org/TR/xmldsig-core/) y del [ETSI](https://uri.etsi.org/01903/v1.3.2/), y no se publican con el paquete.
