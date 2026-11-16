#!/usr/bin/env node
/* Inlines css/styles.css and every <script src> in index.html into one self-contained file: dist/index.html.
 * Useful for sharing a single file, hosting where relative paths break, or opening straight from disk.
 * Usage: node scripts/bundle.js [out-path] */
const fs = require('fs'), path = require('path');
const root = path.join(__dirname, '..');
const out = process.argv[2] || path.join(root, 'dist', 'index.html');
let html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');

html = html.replace(/<link rel="stylesheet" href="([^"]+)">/g, (_, href) => '<style>\n' + fs.readFileSync(path.join(root, href), 'utf8') + '\n</style>');
html = html.replace(/<script src="([^"]+)"><\/script>/g, (_, src) => {
  const js = fs.readFileSync(path.join(root, src), 'utf8');
  if (/<\/script/i.test(js)) throw new Error(src + ' contains "</script", which would end the inline block early.');
  return '<script>\n' + js + '\n</script>';
});
if (/<script src=|<link rel="stylesheet"/.test(html)) throw new Error('Some external references were not inlined.');

fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, html);
console.log('Wrote ' + path.relative(process.cwd(), out) + ' (' + Math.round(html.length / 1024) + ' KB)');
