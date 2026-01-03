import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { createRequire } from "module";

import HtmlWebpackPlugin from "html-webpack-plugin";
import CleanWebpackPlugin from "clean-webpack-plugin";
import CopyWebpackPlugin from 'copy-webpack-plugin';
import MiniCssExtractPlugin from "mini-css-extract-plugin";
import HtmlWebpackInlineSVGPlugin from 'html-webpack-inline-svg-plugin';

const outputDirectory = "dist";
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const require = createRequire(import.meta.url);

export default (env, argv) => {
    const devMode = argv.mode !== "production";
    return {
        entry: "./src/client/index.js",
        devtool: "source-map",
        experiments: {
            outputModule: true
        },
        output: {
            path: join(__dirname, outputDirectory),
            filename: "bundle.js",
            module: true,
            chunkFormat: "module",
            publicPath: devMode ? '/' : '/digitaljs/',
        },
        // Add this inside the export function, at the same level as 'entry' or 'output'
        resolve: {
            alias: {
                // This forces the app to look for the binaries in the right place
                'verilator_bin.js': join(__dirname, 'node_modules/yosys2digitaljs/dist/verilator_bin.js'),
            }
        },
        target: "web",
        module: {
            rules: [
                {
                    test: /\.mjs/,
                    use: {
                        loader: "babel-loader",
                        options: {
                            plugins: [
                                "@babel/plugin-proposal-class-properties"
                            ]
                        }
                    }
                },
                {
                    test: /\.css$/,
                    use: [devMode ? "style-loader" : MiniCssExtractPlugin.loader, "css-loader"]
                },
                {
                    test: /\.scss$/,
                    use: [devMode ? "style-loader" : MiniCssExtractPlugin.loader, "css-loader", "sass-loader"]
                },
                {
                    test: /\.(png|woff|woff2|eot|ttf|svg)$/,
                    type: 'asset'
                },
                {
                    test: require.resolve('jquery'),
                    loader: 'expose-loader',
                    options: {
                        exposes: ['$']
                    }
                },
                {
                    test: /\.svg$/,
                    type: "asset/inline",
                    // Inline assets with the "inline" query parameter.
                    resourceQuery: /inline/,
                },
            ]
        },
        devServer: {
            port: 3000,
            open: true,
            headers: {
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cross-Origin-Embedder-Policy": "require-corp",
            },
            proxy: {
                "/api": "http://localhost:8080"
            }
        },
        plugins: [
            new CleanWebpackPlugin(),
            new HtmlWebpackPlugin({
                template: "./public/index.html",
                inject: 'head',
                scriptLoading: 'module'
    //            favicon: "./public/favicon.ico"
            }),
            new HtmlWebpackInlineSVGPlugin(),
            new CopyWebpackPlugin({
                patterns: [
                    { from: 'public/coi-serviceworker.js', to: '.' },
                    { from: 'public/*.+(ico|png|svg|webmanifest)', to: '[name][ext]' },
                    // Updated paths for nested node_modules
                    { from: 'node_modules/yosys2digitaljs/verilator_bin.js', to: '.' },
                    { from: 'node_modules/yosys2digitaljs/verilator_bin.wasm', to: '.' },
                    { from: 'node_modules/@yowasp/yosys/yosys.js', to: '.' },
                    { from: 'node_modules/@yowasp/yosys/yosys.wasm', to: '.' },
                    { from: 'node_modules/yosys2digitaljs/tests/*.sv', to: 'examples/[name][ext]' }
                ]
            })
        ].concat(devMode ? [] : [new MiniCssExtractPlugin()]),
        optimization: {
            splitChunks: false,
            runtimeChunk: false,
        }
    };
};

