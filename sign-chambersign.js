const fs = require('fs');
const PKCS7Sign = require('./dist/helpers/PKCS7Sign');
const ChamberSigner = require('./dist/helpers/ChamberSigner');

(async() => {
  const signatureImageBytes = fs.readFileSync("./data/signature.png"); 
  const unsignedPdfBuffer = fs.readFileSync("./data/unsigned.pdf");
  const signedPdfBuffer = await PKCS7Sign.sign(unsignedPdfBuffer, "", signatureImageBytes, 400, 100, 'CODE', ChamberSigner);
  // Write the signed file
  fs.writeFileSync("./data/signed-chambersign.pdf", signedPdfBuffer);
  PKCS7Sign.verify('./data/signed-chambersign.pdf');
})();

