"use strict";

const graphene = require('graphene-pk11');

const forge = require('node-forge');

class ChamberSigner extends Object {
  static loadModule = passphrase => {
    let Module = graphene.Module;
    this.module = Module.load("/usr/lib/WebSmartPack/libidop11.so", "Chambersign");
    this.module.initialize();
    this.session = this.module.getSlots(0).open();
    this.session.login(passphrase);
  };
  static closeModule = () => {
    this.session.logout();
    this.module.finalize();
  };
  static getCertificate = () => {
    let certsObj = this.session.find({
      class: graphene.ObjectClass.CERTIFICATE
    });
    let certs = certsObj.innerItems;
    let cert = this.session.getObject(certs[0]);
    let decoded = forge.asn1.fromDer(cert.value.toString('binary'));
    return forge.pki.certificateFromAsn1(decoded);
  };
  static signPkcs11 = async digest => {
    // https://stackoverflow.com/a/47106124
    const prefix = Buffer.from([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]); // console.log("Ready to sign digest ");
    // console.log(digest);
    // var base64Data = forge.util.encode64(digest.getBytes());
    // console.log("Base64 digest", base64Data);
    // digest = forge.util.createBuffer(forge.util.decode64(base64Data));
    // console.log("New digest", digest);

    let buf = Buffer.concat([prefix, Buffer.from(digest.toHex(), 'hex')]);
    let keys = this.session.find({
      class: graphene.ObjectClass.PRIVATE_KEY
    }); // console.log("Keys: ", keys);

    let pkeyBuffer = keys.innerItems[0]; // console.log("KeyBuffer: ", pkeyBuffer);

    let pkeyObject = this.session.getObject(pkeyBuffer);
    let sign = this.session.createSign("RSA_PKCS", pkeyObject); // console.log("Just before sign", buf.length);

    let result = sign.once(buf).toString('binary');
    return result;
  };
}

module.exports = ChamberSigner;