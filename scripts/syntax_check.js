const fs = require('fs');
try {
  const src = fs.readFileSync('backend/server.js','utf8');
  new Function(src);
  console.log('OK');
} catch (e) {
  console.error(e && e.stack ? e.stack : e);
  process.exit(1);
}
