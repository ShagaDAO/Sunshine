const path = require('path');
const { ProvidePlugin } = require('webpack');

module.exports = {
  mode: 'development',
  entry: './src_assets/common/assets/web/typescript_shaga/shagaUIManager.ts',
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'src_assets/common/assets/web/libs')
  },
  module: {
    rules: [
      {
        test: /\.m?[jt]sx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
      {
        test: /\.m?[jt]sx?$/,
        enforce: 'pre',
        use: ['source-map-loader'],
      },
      {
        test: /\.m?[jt]sx?$/,
        resolve: {
          fullySpecified: false,
        },
      },
    ],
  },
  plugins: [
    new ProvidePlugin({
      process: 'process/browser',
    }),
  ],
  resolve: {
    extensions: ['.ts', '.tsx', '.js'],
    fallback: {
      assert: require.resolve('assert'),
      buffer: require.resolve('buffer'),
      crypto: require.resolve('crypto-browserify'),
      http: require.resolve('stream-http'),
      https: require.resolve('https-browserify'),
      stream: require.resolve('stream-browserify'),
      url: require.resolve('url/'),
      zlib: require.resolve('browserify-zlib'),
      path: require.resolve('path-browserify'),
      querystring: require.resolve("querystring-es3"),
    },
  },
  ignoreWarnings: [/Failed to parse source map/],
};