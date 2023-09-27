const path = require('path');
const webpack = require('webpack');

module.exports = {
  mode: 'development',
  entry: './src_assets/common/assets/web/libs/shagaUIManager.js', // your main JavaScript file
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'src_assets/common/assets/web/libs'),
  },
  resolve: {
    extensions: ['.ts', '.js'],
    fallback: {
      "crypto": require.resolve("crypto-browserify"),
      "buffer": require.resolve("buffer/"),
      "stream": require.resolve("stream-browserify")
    }
  },

  plugins: [
    new webpack.ProvidePlugin({
      Buffer: ['buffer', 'Buffer'],
    }),
  ],
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
};
