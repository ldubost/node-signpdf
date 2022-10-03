const fs = require('fs');
const PKCS7Sign = require('./dist/helpers/PKCS7Sign');

(async() => {
  const signatureImageBytes = fs.readFileSync("./data/signature.png"); 
  const p12Buffer = fs.readFileSync('./data/certificate.p12');
  const certificate = p12Buffer.toString("base64");
  const unsignedPdfBuffer = fs.readFileSync("./data/unsigned.pdf");
  const signedPdfBuffer = await PKCS7Sign.sign(unsignedPdfBuffer, certificate, signatureImageBytes, 400, 100, '');
  // Write the signed file
  fs.writeFileSync("./data/signed-certificate.pdf", signedPdfBuffer);
  PKCS7Sign.verify('./data/signed-certificate.pdf');
})();

