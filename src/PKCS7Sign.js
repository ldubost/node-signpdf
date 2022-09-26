import {
    PDFDocument,
    PDFName,
    PDFNumber,
    PDFHexString,
    PDFString,
    PDFArray,
    CharCodes,
    drawRectangle,
    drawImage,
    rgb,
    degrees,
} from 'pdf-lib';
import PDFArrayCustom from './PDFArrayCustom';
import signer from './signpdf';

export class PKCS7Sign {
    constructor() {
    }

    extractSignature(pdf) {
        let byteRangePos = pdf.lastIndexOf('/ByteRange[');
        if (byteRangePos === -1) byteRangePos = pdf.lastIndexOf('/ByteRange [');

        const byteRangeEnd = pdf.indexOf(']', byteRangePos);
        const byteRange = pdf.slice(byteRangePos, byteRangeEnd + 1).toString();
        const byteRangeNumbers = /(\d+) +(\d+) +(\d+) +(\d+)/.exec(byteRange);
        const byteRangeArr = byteRangeNumbers[0].split(' ');

        const signedData = Buffer.concat([
            pdf.slice(parseInt(byteRangeArr[0]), parseInt(byteRangeArr[1])),
            pdf.slice(
                parseInt(byteRangeArr[2]),
                parseInt(byteRangeArr[2]) + parseInt(byteRangeArr[3]),
            ),
        ]);
        let signatureHex = pdf
            .slice(
                parseInt(byteRangeArr[0]) + (parseInt(byteRangeArr[1]) + 1),
                parseInt(byteRangeArr[2]) - 1,
            )
            .toString('binary');
        signatureHex = signatureHex.replace(/(?:00)*$/, '');
        const signature = Buffer.from(signatureHex, 'hex').toString('binary');
        const reasonPos = pdf.lastIndexOf('/Reason (');
        const reasonEnd = pdf.indexOf(')', reasonPos);
        const reason = (reasonPos == -1) ? '' : pdf.slice(reasonPos + 9, reasonEnd).toString();
        let datePos = pdf.lastIndexOf('/M (D:');
        let nbPos = 6;
        if (datePos == -1) {
            datePos = pdf.lastIndexOf('/M(D:');
            nbPos = 5;
        }
        const dateEnd = pdf.indexOf(')', datePos);
        const date = (datePos == -1) ? '' : pdf.slice(datePos + nbPos, dateEnd).toString();
        return {
            signature, signedData, reason, date,
        };
    }

    verify(signedPDF) {
        const pdf = fs.readFileSync(signedPDF);
        console.log(`**** validating file ${signedPDF} ****`);
        const extractedData = this.extractSignature(pdf);
        const p7Asn1 = forge.asn1.fromDer(extractedData.signature);
        const message = forge.pkcs7.messageFromAsn1(p7Asn1);
        const sig = message.rawCapture.signature;
        const attrs = message.rawCapture.authenticatedAttributes;
        const set = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, attrs);
        const buf = Buffer.from(forge.asn1.toDer(set).data, 'binary');
        console.log('Message: ', message);
        console.log('Reason: ', extractedData.reason);
        console.log('Date: ', extractedData.date);
        const cert = forge.pki.certificateToPem(message.certificates[0]);
        const certDetails = this.extractSingleCertificateDetails(message.certificates[0]);
        const {oids} = forge.pki;
        var signatureDate = '';
        const signerInfos = message.rawCapture.signerInfos[0].value;
        var signatureDate = null;
        for (var i = 0, l = signerInfos.length; i < l; ++i) {
            try {
                // console.log("Attr: ", i, " " , signerInfos[i].value[0].value);
                // console.log("Attr: ", i, " " , forge.asn1.derToOid(signerInfos[i].value[0].value));
                // console.log("Attr: ", i, " " , signerInfos[i].value[1].value[0].value);
                if (forge.asn1.derToOid(signerInfos[i].value[0].value) === oids.signingTime) {
                    signatureDate = signerInfos[i].value[1].value[0].value;
                }
            } catch (e) {}
        }
        const attrDigest3 = null;
        for (var i = 0, l = attrs.length; i < l; ++i) {
            try {
                // console.log("Attr: ", i, " " , attrs[i].value[0].value);
                // console.log("Attr: ", i, " " , forge.asn1.derToOid(attrs[i].value[0].value));
                if (forge.asn1.derToOid(attrs[i].value[0].value) === oids.signingTime) {
                    signatureDate = attrs[i].value[1].value[0].value;
                }
            } catch (e) {}
        }
        if (extractedData.date != '') signatureDate = extractedData.date;
        console.log('File signed on ', signatureDate);
        const verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(buf);
        const validAuthenticatedAttributes = verifier.verify(cert, sig, 'binary');
        if (!validAuthenticatedAttributes) throw new Error('Wrong authenticated attributes');
        const hash = crypto.createHash('SHA256');
        const data = extractedData.signedData;
        hash.update(data);
        const fullAttrDigest = attrs.find((attr) => forge.asn1.derToOid(attr.value[0].value) === oids.messageDigest);
        const attrDigest = fullAttrDigest.value[1].value[0].value;
        const dataDigest = hash.digest();
        const validContentDigest = dataDigest.toString('binary') === attrDigest;
        if (!validContentDigest) throw new Error('Wrong content digest');
        console.log('**** FILE VALID ****');
    }

    mapEntityAtrributes(attrs) {
        attrs.reduce((agg, {name, value}) => {
            if (!name) return agg;
            agg[name] = value;
            return agg;
        }, {});
    }

    extractSingleCertificateDetails(cert) {
        const {issuer, subject, validity} = cert;
        return {
            issuedBy: this.mapEntityAtrributes(issuer.attributes),
            issuedTo: this.mapEntityAtrributes(subject.attributes),
            validityPeriod: validity,
            pemCertificate: forge.pki.certificateToPem(cert),
        };
    }

    extractCertificatesDetails(certs) {
        certs
            .map(this.extractSingleCertificateDetails)
            .map((cert, i) => {
                if (i) return cert;
                return {
                    clientCertificate: true,
                    ...cert,
                };
            });
    }

    async sign(pdfBuffer, certificate, signatureImageBytes, x, y, w, h, signatureMessage, passphrase = '') {
        // The PDF we're going to sign
        const pdfDoc = await PDFDocument.load(pdfBuffer);
        this.prepareSignPDFDoc(pdfDoc, signatureImageBytes, x, y, w, h, signatureMessage);
        const modifiedPdfBytes = await pdfDoc.save({useObjectStreams: false});
        const modifiedPdfBuffer = Buffer.from(modifiedPdfBytes);
        return await this.signPDFBuffer(modifiedPdfBuffer, certificate, passphrase);
    }

    async signPDFBuffer(pdfBuffer, certificate, passphrase = '') {
        // The p12 certificate we're going to sign with
        const p12Buffer = new Buffer(certificate, 'base64');
        const signObj = signer;
        const signedPdfBuffer = signObj.sign(pdfBuffer, p12Buffer, {
            passphrase: '',
        });
        return signedPdfBuffer;
    }

    async signPDFDoc(pdfDoc, certificate, passphrase = '') {
        const modifiedPdfBytes = await pdfDoc.save({useObjectStreams: false});
        const modifiedPdfBuffer = Buffer.from(modifiedPdfBytes);
        return await this.signPDFBuffer(modifiedPdfBuffer, certificate, passphrase);
    }

    async prepareSignPDFDoc(pdfDoc, signatureImageBytes, x, y, w, h, signatureMessage) {
        // This length can be derived from the following `node-signpdf` error message:
        //   ./node_modules/node-signpdf/dist/signpdf.js:155:19
        const SIGNATURE_LENGTH = 8192;

        const pages = pdfDoc.getPages();

        const BYTE_RANGE_PLACEHOLDER = '**********';
        const ByteRange = PDFArrayCustom.withContext(pdfDoc.context);
        ByteRange.push(PDFNumber.of(0));
        ByteRange.push(PDFName.of(BYTE_RANGE_PLACEHOLDER));
        ByteRange.push(PDFName.of(BYTE_RANGE_PLACEHOLDER));
        ByteRange.push(PDFName.of(BYTE_RANGE_PLACEHOLDER));

        const signatureDict = pdfDoc.context.obj({
            Type: 'Sig',
            Filter: 'Adobe.PPKLite',
            SubFilter: 'adbe.pkcs7.detached',
            ByteRange,
            Contents: PDFHexString.of('A'.repeat(SIGNATURE_LENGTH)),
            Reason: PDFString.of(signatureMessage),
            M: PDFString.fromDate(new Date()),
        });
        const signatureDictRef = pdfDoc.context.register(signatureDict);
        const signatureImageName = 'Signature';
        const image = await pdfDoc.embedPng(signatureImageBytes);
        const width = w;
        const height = h;
        const widgetDict = pdfDoc.context.obj({
            Type: 'Annot',
            Subtype: 'Widget',
            FT: 'Sig',
            Rect: [x, y, x + width, y + height],
            V: signatureDictRef,
            T: PDFString.of('Signature1'),
            F: 4,
            P: pages[0].ref,
        });
        const widgetDictRef = pdfDoc.context.register(widgetDict);

        // Add our signature widget to the first page
        pages[0].node.set(PDFName.of('Annots'), pdfDoc.context.obj([widgetDictRef]));

        // Create an AcroForm object containing our signature widget
        pdfDoc.catalog.set(
            PDFName.of('AcroForm'),
            pdfDoc.context.obj({
                SigFlags: 3,
                Fields: [widgetDictRef],
            }),
        );

        const form = pdfDoc.getForm();
        const sig = form.getSignature('Signature1');
        sig.acroField.getWidgets().forEach((widget) => {
            const {context} = widget.dict;
            const {width, height} = widget.getRectangle();

            const appearance = [
                ...drawRectangle({
                    x: 0,
                    y: 0,
                    width,
                    height,
                    borderWidth: 2,
                    color: rgb(1, 1, 1),
                    borderColor: rgb(0, 0, 0),
                    rotate: degrees(0),
                    xSkew: degrees(0),
                    ySkew: degrees(0),
                }),

                ...drawImage(signatureImageName, {
                    x: 0,
                    y: 0,
                    width,
                    height,
                    rotate: degrees(0),
                    xSkew: degrees(0),
                    ySkew: degrees(0),
                }),
            ];

            const stream = context.formXObject(appearance, {
                Resources: {XObject: {[signatureImageName]: image.ref}},
                BBox: context.obj([0, 0, width, height]),
                Matrix: context.obj([1, 0, 0, 1, 0, 0]),
            });
            const streamRef = context.register(stream);

            widget.setNormalAppearance(streamRef);
        });
    }
}

export default PKCS7Sign;
