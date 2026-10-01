/**
 * Renders the PNG icons from public/favicon.svg: favicon.png for browsers
 * without SVG favicons, apple-touch-icon.png for iOS home screens.
 *
 * Run with `npm run favicon` after changing the SVG. The PNGs are committed,
 * like og.png.
 */

import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';

const here = dirname(fileURLToPath(import.meta.url));
const pub = resolve(here, '../public');
const svg = resolve(pub, 'favicon.svg');

// Sizes match the `sizes` attributes in Base.astro.
async function render(name, size, flatten) {
  // Rasterized at 8x the target, then scaled down. The SVG's viewBox is 32px.
  let img = sharp(svg, { density: (72 * 8 * size) / 32 }).resize(size, size);
  if (flatten) img = img.flatten({ background: flatten });
  await img.png({ compressionLevel: 9 }).toFile(resolve(pub, name));
  console.log(`wrote ${resolve(pub, name)}`);
}

await render('favicon.png', 32);
// iOS fills transparency with black and rounds the corners itself: the
// background goes to the edges instead.
await render('apple-touch-icon.png', 180, '#191713');
