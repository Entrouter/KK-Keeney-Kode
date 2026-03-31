const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const katex = require('katex');
const puppeteer = require('puppeteer');

// --- Resolve input file from CLI argument ---
const inputFile = process.argv[2] || 'docs/KK_COMBINED_PAPER.md';
const baseName = path.basename(inputFile, '.md');

// --- Step 1: Use pandoc to convert markdown to HTML ---
// Pandoc's parser correctly preserves math inside $...$ and $$...$$ delimiters,
// unlike `marked` which mangles underscores, pipes, and backslash sequences.
console.log(`Step 1: Converting ${inputFile} to HTML via pandoc...`);
const rawHtml = execSync(
	`pandoc ${inputFile} -t html5 --mathjax --standalone --wrap=none`,
	{ encoding: 'utf8', maxBuffer: 50 * 1024 * 1024, cwd: __dirname }
);

// --- Step 2: Render math with KaTeX server-side ---
console.log('Step 2: Rendering math with KaTeX...');
let inlineCount = 0;
let displayCount = 0;
let errorCount = 0;

// Pandoc HTML-encodes characters inside math spans (e.g. ' -> &#39;, < -> &lt;).
// We must decode these back to raw LaTeX before passing to KaTeX.
function decodeHtmlEntities(str) {
	return str
		.replace(/&lt;/g, '<')
		.replace(/&gt;/g, '>')
		.replace(/&amp;/g, '&')
		.replace(/&#39;/g, "'")
		.replace(/&quot;/g, '"')
		.replace(/&#x27;/g, "'")
		.replace(/&#(\d+);/g, (_, code) => String.fromCharCode(Number(code)));
}

// Pandoc --mathjax outputs:
//   inline: <span class="math inline">\(expression\)</span>
//   display: <span class="math display">\[expression\]</span>
let html = rawHtml;

// Render display math first (greedy, may span lines)
html = html.replace(/<span class="math display">\\\[([\s\S]*?)\\\]<\/span>/g, (match, expr) => {
	try {
		displayCount++;
		return katex.renderToString(decodeHtmlEntities(expr.trim()), { displayMode: true, throwOnError: false });
	} catch (e) {
		errorCount++;
		console.error(`  Display math error: ${expr.substring(0, 60)}...`);
		return match;
	}
});

// Render inline math
html = html.replace(/<span class="math inline">\\\(([\s\S]*?)\\\)<\/span>/g, (match, expr) => {
	try {
		inlineCount++;
		return katex.renderToString(decodeHtmlEntities(expr.trim()), { displayMode: false, throwOnError: false });
	} catch (e) {
		errorCount++;
		console.error(`  Inline math error: ${expr.substring(0, 60)}...`);
		return match;
	}
});

console.log(`  Rendered ${inlineCount} inline + ${displayCount} display = ${inlineCount + displayCount} total math expressions`);
if (errorCount > 0) console.log(`  ${errorCount} errors`);

// --- Step 3: Inject KaTeX CSS with embedded fonts ---
console.log('Step 3: Injecting KaTeX CSS with embedded fonts...');
const fontsDir = path.resolve(__dirname, 'node_modules/katex/dist/fonts');
let katexCss = fs.readFileSync(
	path.resolve(__dirname, 'node_modules/katex/dist/katex.min.css'),
	'utf8'
);

// Convert all font URLs to inline base64 data URIs
katexCss = katexCss.replace(/url\(fonts\/([^)]+)\)/g, (match, fontFile) => {
	const fontPath = path.join(fontsDir, fontFile);
	if (fs.existsSync(fontPath)) {
		const fontData = fs.readFileSync(fontPath).toString('base64');
		const ext = path.extname(fontFile).slice(1);
		const mime = ext === 'woff2' ? 'font/woff2' : ext === 'woff' ? 'font/woff' : 'font/ttf';
		return `url(data:${mime};base64,${fontData})`;
	}
	return match;
});

// Paper styling
const paperCss = `
body {
  font-family: 'Times New Roman', 'DejaVu Serif', Georgia, serif;
  font-size: 11pt;
  line-height: 1.5;
  color: #1a1a1a;
  max-width: 100%;
  margin: 0;
  padding: 0;
}
h1 { font-size: 1.6em; margin-top: 1.2em; margin-bottom: 0.4em; }
h2 { font-size: 1.35em; margin-top: 1.1em; margin-bottom: 0.3em; }
h3 { font-size: 1.15em; margin-top: 1em; margin-bottom: 0.3em; }
h4 { font-size: 1.05em; margin-top: 0.9em; margin-bottom: 0.2em; }
table { border-collapse: collapse; margin: 1em auto; font-size: 0.92em; }
th, td { border: 1px solid #888; padding: 4px 8px; }
th { background: #f0f0f0; }
blockquote { border-left: 3px solid #ccc; padding-left: 1em; color: #555; margin: 1em 0; }
code { font-family: 'Consolas', 'DejaVu Sans Mono', monospace; font-size: 0.9em; background: #f5f5f5; padding: 1px 3px; border-radius: 2px; }
pre { background: #f5f5f5; padding: 0.8em; border-radius: 4px; overflow-x: auto; font-size: 0.85em; }
pre code { background: none; padding: 0; }
hr { border: none; border-top: 1px solid #ccc; margin: 1.5em 0; }
.katex-display { margin: 0.8em 0; }
.katex { font-size: 1.0em; }
a { color: #1a5276; text-decoration: none; }

/* GitHub-style note/warning admonitions */
.markdown-alert { border-left: 4px solid #0969da; padding: 0.5em 1em; margin: 1em 0; background: #f6f8fa; }
`;

// Inject CSS into <head>
html = html.replace('</head>', `<style>${katexCss}\n${paperCss}</style>\n</head>`);

// Remove MathJax script tags that pandoc injected (we rendered server-side with KaTeX)
html = html.replace(/<script[^>]*mathjax[^>]*>[\s\S]*?<\/script>/gi, '');
html = html.replace(/<script[^>]*type="text\/x-mathjax[^>]*>[\s\S]*?<\/script>/gi, '');

// Write intermediate HTML for debugging
const htmlPath = path.resolve(__dirname, `docs/${baseName}_render.html`);
fs.writeFileSync(htmlPath, html);
console.log(`  Wrote intermediate HTML: ${htmlPath}`);

// --- Step 4: Convert to PDF with Puppeteer ---
console.log('Step 4: Rendering PDF with Puppeteer...');
(async () => {
	const browser = await puppeteer.launch({
		headless: 'new',
		args: ['--no-sandbox', '--disable-setuid-sandbox'],
	});
	const page = await browser.newPage();

	await page.setContent(html, { waitUntil: 'networkidle0', timeout: 60000 });

	const pdfPath = path.resolve(__dirname, `docs/${baseName}.pdf`);
	await page.pdf({
		path: pdfPath,
		format: 'A4',
		margin: { top: '20mm', bottom: '20mm', left: '25mm', right: '25mm' },
		printBackground: true,
		displayHeaderFooter: false,
	});

	await browser.close();
	console.log(`PDF generated: ${pdfPath}`);

	// Quick validation: check for any remaining unrendered math
	const finalHtml = fs.readFileSync(htmlPath, 'utf8');
	const remaining = (finalHtml.match(/<span class="math (inline|display)">/g) || []).length;
	if (remaining > 0) {
		console.warn(`WARNING: ${remaining} math expressions may not have been rendered`);
	} else {
		console.log('All math expressions rendered successfully!');
	}
})();
