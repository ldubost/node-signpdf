"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.SignPdf = exports.DEFAULT_BYTE_RANGE_PLACEHOLDER = void 0;
Object.defineProperty(exports, "SignPdfError", {
  enumerable: true,
  get: function () {
    return _SignPdfError.default;
  }
});
exports.default = void 0;

var _nodeForge = _interopRequireDefault(require("node-forge"));

var _SignPdfError = _interopRequireDefault(require("./SignPdfError"));

var _helpers = require("./helpers");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const DEFAULT_BYTE_RANGE_PLACEHOLDER = '**********';
exports.DEFAULT_BYTE_RANGE_PLACEHOLDER = DEFAULT_BYTE_RANGE_PLACEHOLDER;

class SignPdf {
  constructor() {
    this.lastSignature = null;
  }

  sign(pdfBuffer, p12Buffer, additionalOptions = {}) {
    const options = {
      asn1StrictParsing: false,
      passphrase: '',
      ...additionalOptions
    };

    if (!(pdfBuffer instanceof Buffer)) {
      throw new _SignPdfError.default('PDF expected as Buffer.', _SignPdfError.default.TYPE_INPUT);
    }

    if (!(p12Buffer instanceof Buffer)) {
      throw new _SignPdfError.default('p12 certificate expected as Buffer.', _SignPdfError.default.TYPE_INPUT);
    }

    let {
      pdf,
      placeholderLength,
      byteRange
    } = getSignablePdfBuffer(pdfBuffer); // Convert Buffer P12 to a forge implementation.

    const forgeCert = _nodeForge.default.util.createBuffer(p12Buffer.toString('binary'));

    const p12Asn1 = _nodeForge.default.asn1.fromDer(forgeCert);

    const p12 = _nodeForge.default.pkcs12.pkcs12FromAsn1(p12Asn1, options.asn1StrictParsing, options.passphrase); // Extract safe bags by type.
    // We will need all the certificates and the private key.


    const certBags = p12.getBags({
      bagType: _nodeForge.default.pki.oids.certBag
    })[_nodeForge.default.pki.oids.certBag];

    const keyBags = p12.getBags({
      bagType: _nodeForge.default.pki.oids.pkcs8ShroudedKeyBag
    })[_nodeForge.default.pki.oids.pkcs8ShroudedKeyBag];

    const privateKey = keyBags[0].key; // Here comes the actual PKCS#7 signing.

    const p7 = _nodeForge.default.pkcs7.createSignedData(); // Start off by setting the content.


    p7.content = _nodeForge.default.util.createBuffer(pdf.toString('binary')); // Then add all the certificates (-cacerts & -clcerts)
    // Keep track of the last found client certificate.
    // This will be the public key that will be bundled in the signature.

    let certificate;
    Object.keys(certBags).forEach(i => {
      const {
        publicKey
      } = certBags[i].cert;
      p7.addCertificate(certBags[i].cert); // Try to find the certificate that matches the private key.

      if (privateKey.n.compareTo(publicKey.n) === 0 && privateKey.e.compareTo(publicKey.e) === 0) {
        certificate = certBags[i].cert;
      }
    });

    if (typeof certificate === 'undefined') {
      throw new _SignPdfError.default('Failed to find a certificate that matches the private key.', _SignPdfError.default.TYPE_INPUT);
    }

    console.log(certificate); // Add a sha256 signer. That's what Adobe.PPKLite adbe.pkcs7.detached expects.

    p7.addSigner({
      key: privateKey,
      certificate,
      digestAlgorithm: _nodeForge.default.pki.oids.sha256,
      authenticatedAttributes: [{
        type: _nodeForge.default.pki.oids.contentType,
        value: _nodeForge.default.pki.oids.data
      }, {
        type: _nodeForge.default.pki.oids.messageDigest // value will be auto-populated at signing time

      }, {
        type: _nodeForge.default.pki.oids.signingTime,
        // value can also be auto-populated at signing time
        // We may also support passing this as an option to sign().
        // Would be useful to match the creation time of the document for example.
        value: new Date()
      }]
    }); // Sign in detached mode.

    p7.sign({
      detached: true
    });
    let {
      signedPdf,
      hexSignature
    } = embedP7inPdf(pdf, p7, byteRange, placeholderLength);
    console.log(hexSignature);
    this.lastSignature = hexSignature;
    return signedPdf;
  }

  async signWithPkcs11(pdfBuffer, pkcsSigner, passphrase) {
    console.log("Start signWithPkcs11");

    if (!(pdfBuffer instanceof Buffer)) {
      throw new _SignPdfError.default('PDF expected as Buffer.', _SignPdfError.default.TYPE_INPUT);
    }

    let {
      pdf,
      placeholderLength,
      byteRange
    } = getSignablePdfBuffer(pdfBuffer);

    const p7 = _nodeForge.default.pkcs7.createSignedData();

    try {
      console.log("Before module load");
      pkcsSigner.loadModule(passphrase);
      console.log("After module load");
      let signer = {};

      signer.sign = async (md, algo) => {
        console.log("In signature");
        let digest = md.digest();
        console.log("Ready to sign digest ", digest);
        const signature = await pkcsSigner.signPkcs11(digest);
        console.log("Signature ", signature);
        return signature;
      };

      console.log("Before getCert");
      let certificate = await pkcsSigner.getCertificate();
      console.log("Certificate: ", certificate); // Start off by setting the content.

      p7.content = _nodeForge.default.util.createBuffer(pdf.toString('binary'));
      p7.addCertificate(certificate); // Add a sha256 signer. That's what Adobe.PPKLite adbe.pkcs7.detached expects.

      p7.addSigner({
        key: signer,
        certificate,
        digestAlgorithm: _nodeForge.default.pki.oids.sha256,
        authenticatedAttributes: [{
          type: _nodeForge.default.pki.oids.contentType,
          value: _nodeForge.default.pki.oids.data
        }, {
          type: _nodeForge.default.pki.oids.messageDigest // value will be auto-populated at signing time

        }, {
          type: _nodeForge.default.pki.oids.signingTime,
          // value can also be auto-populated at signing time
          // We may also support passing this as an option to sign().
          // Would be useful to match the creation time of the document for example.
          value: new Date()
        }]
      });
      p7.sign({
        detached: true
      });
    } catch (e) {
      console.error("Signpdf exception ", e);
    } finally {
      console.log("Closing pkcsSigner module");
      pkcsSigner.closeModule();
    } // walk through all the internally assigned promises we now need to wait to resolve


    p7.signerInfos = await Promise.all(p7.signerInfos.map(async signerInfo => {
      signerInfo.value = await Promise.all(signerInfo.value.map(async value => {
        value.value = await value.value;
        return value;
      }));
      return signerInfo;
    })); // just for completeness, assign resolved values to signer's signature

    p7.signers = await Promise.all(p7.signers.map(async p7Signer => {
      p7Signer.signature = await p7Signer.signature;
      return p7Signer;
    }));
    console.log("before embed in pdf");
    let {
      signedPdf,
      hexSignature
    } = embedP7inPdf(pdf, p7, byteRange, placeholderLength);
    this.lastSignature = hexSignature;
    console.log(hexSignature);
    console.log("returning signedPdf");
    return signedPdf;
  }

}

exports.SignPdf = SignPdf;

const embedP7inPdf = (pdf, p7, byteRange, placeholderLength) => {
  // Check if the PDF has a good enough placeholder to fit the signature.
  const raw = _nodeForge.default.asn1.toDer(p7.toAsn1()).getBytes(); // placeholderLength represents the length of the HEXified symbols but we're
  // checking the actual lengths.


  if (raw.length * 2 > placeholderLength) {
    throw new _SignPdfError.default(`Signature exceeds placeholder length: ${raw.length * 2} > ${placeholderLength}`, _SignPdfError.default.TYPE_INPUT);
  }

  let signature = Buffer.from(raw, 'binary').toString('hex'); // Store the HEXified signature. At least useful in tests.

  let hexSignature = signature; // Pad the signature with zeroes so the it is the same length as the placeholder

  signature += Buffer.from(String.fromCharCode(0).repeat(placeholderLength / 2 - raw.length)).toString('hex'); // Place it in the document.

  let signedPdf = Buffer.concat([pdf.slice(0, byteRange[1]), Buffer.from(`<${signature}>`), pdf.slice(byteRange[1])]);
  return {
    signedPdf,
    hexSignature
  };
};

const getSignablePdfBuffer = pdfBuffer => {
  let pdf = (0, _helpers.removeTrailingNewLine)(pdfBuffer);
  let byteRangePlaceholderStr = DEFAULT_BYTE_RANGE_PLACEHOLDER; // Find the ByteRange placeholder.

  const byteRangePlaceholder = [0, `/${byteRangePlaceholderStr}`, `/${byteRangePlaceholderStr}`, `/${byteRangePlaceholderStr}`];
  const byteRangeString = `/ByteRange [${byteRangePlaceholder.join(' ')}]`;
  const byteRangePos = pdf.indexOf(byteRangeString);

  if (byteRangePos === -1) {
    throw new _SignPdfError.default(`Could not find ByteRange placeholder: ${byteRangeString}`, _SignPdfError.default.TYPE_PARSE);
  } // Calculate the actual ByteRange that needs to replace the placeholder.


  const byteRangeEnd = byteRangePos + byteRangeString.length;
  const contentsTagPos = pdf.indexOf('/Contents ', byteRangeEnd);
  const placeholderPos = pdf.indexOf('<', contentsTagPos);
  const placeholderEnd = pdf.indexOf('>', placeholderPos);
  const placeholderLengthWithBrackets = placeholderEnd + 1 - placeholderPos;
  const placeholderLength = placeholderLengthWithBrackets - 2;
  const byteRange = [0, 0, 0, 0];
  byteRange[1] = placeholderPos;
  byteRange[2] = byteRange[1] + placeholderLengthWithBrackets;
  byteRange[3] = pdf.length - byteRange[2];
  let actualByteRange = `/ByteRange [${byteRange.join(' ')}]`;
  actualByteRange += ' '.repeat(byteRangeString.length - actualByteRange.length); // Replace the /ByteRange placeholder with the actual ByteRange

  pdf = Buffer.concat([pdf.slice(0, byteRangePos), Buffer.from(actualByteRange), pdf.slice(byteRangeEnd)]); // Remove the placeholder signature

  pdf = Buffer.concat([pdf.slice(0, byteRange[1]), pdf.slice(byteRange[2], byteRange[2] + byteRange[3])]);
  return {
    pdf,
    placeholderLength,
    byteRange
  };
};

var _default = new SignPdf();

exports.default = _default;