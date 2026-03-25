const fs = require('fs');
const path = require('path');
const markedKatex = require('marked-katex-extension');

const katexCssPath = path.join(path.dirname(require.resolve('katex')), '..', 'dist', 'katex.min.css');
const katexCss = fs.readFileSync(katexCssPath, 'utf8').replace(/url\(fonts\//g, 'url(/fonts/');

module.exports = {
  marked_extensions: [markedKatex({ throwOnError: false, nonStandard: true })],
  css: katexCss + `
    body { font-family: "Times New Roman", Times, serif; font-size: 11pt; line-height: 1.4; }
    h1 { font-size: 16pt; text-align: center; }
    h2 { font-size: 13pt; }
    h3 { font-size: 11.5pt; }
    blockquote { border-left: 3px solid #333; padding: 0.5em 1em; margin: 1em 0; background: #f9f9f9; }
    table { border-collapse: collapse; width: 100%; margin: 0.8em 0; font-size: 10pt; }
    th, td { border: 1px solid #999; padding: 4px 8px; }
    th { background: #eee; }
    code { font-size: 9.5pt; }
    pre { font-size: 9pt; }
  `,
  pdf_options: {
    format: 'A4',
    margin: { top: '20mm', bottom: '20mm', left: '25mm', right: '25mm' },
    printBackground: true,
  },
};
