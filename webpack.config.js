/**
 * Forge webpack build rules.
 *
 * @author Digital Bazaar, Inc.
 *
 * Copyright 2011-2016 Digital Bazaar, Inc.
 */
const path = require('path');

// build multiple outputs
module.exports = [];

// custom setup for each output
// all built files will export the "signpdf" library but with different content
const outputs = [
    // pkcs7sign 
    {
       entry: ['./dist/helpers/PKCS7Sign.js'],
       filenameBase: 'pkcs7sign.all',
    },
    // core signpdf
    {
        entry: ['./dist/signpdf.js'],
        filenameBase: 'signpdf.all',
    },
];

outputs.forEach((info) => {
    // common to bundle and minified
    const common = {
    // each output uses the "signpdf" name but with different contents
        entry: {
            signpdf: info.entry,
        },
        // disable various node shims as signpdf handles this manually
        node: {
            Buffer: true,
            process: false,
            crypto: true,
            setImmediate: false,
        },
    };

    // plain unoptimized unminified bundle
    const bundle = {
        ...common,
        mode: 'development',
        output: {
            path: path.join(__dirname, 'dist'),
            filename: `${info.filenameBase}.js`,
            library: info.library || '[name]',
            libraryTarget: info.libraryTarget || 'umd',
        },
    };
    if (info.library === null) {
        delete bundle.output.library;
    }
    if (info.libraryTarget === null) {
        delete bundle.output.libraryTarget;
    }

    // optimized and minified bundle
    const minify = {
        ...common,
        mode: 'production',
        output: {
            path: path.join(__dirname, 'dist'),
            filename: `${info.filenameBase}.min.js`,
            library: info.library || '[name]',
            libraryTarget: info.libraryTarget || 'umd',
        },
        devtool: 'cheap-module-source-map',
        plugins: [
            /*
      new webpack.optimize.UglifyJsPlugin({
        sourceMap: true,
        compress: {
          warnings: true
        },
        output: {
          comments: false
        }
        //beautify: true
      })
      */
        ],
    };
    if (info.library === null) {
        delete minify.output.library;
    }
    if (info.libraryTarget === null) {
        delete minify.output.libraryTarget;
    }

    module.exports.push(bundle);
    module.exports.push(minify);
});
