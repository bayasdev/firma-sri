# Registro de cambios

## 1.0.0

Primera versión.

- `signXml` firma un comprobante electrónico del SRI con un certificado `.p12`: una firma XAdES-BES envuelta, con RSA-SHA1 como especifica la ficha técnica, o con RSA-SHA256.
- `verifySignature` comprueba la firma de un comprobante y devuelve el certificado que lo firmó y la hora de la firma.
- `readCertificate` lee de un `.p12` el titular, su RUC y su cédula, la entidad de certificación y la vigencia. `certificateHolds` dice si el certificado identifica a un RUC.
- `createSelfSignedCertificate`, en `firma-sri/testing`, crea un certificado autofirmado para pruebas.
