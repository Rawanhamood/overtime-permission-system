const fs=require('fs');
const s=fs.readFileSync('backend/server.js','utf8');
console.log('backticks', (s.split(String.fromCharCode(96)).length-1));
console.log('open_paren', (s.match(/\(/g)||[]).length, 'close_paren', (s.match(/\)/g)||[]).length);
console.log('open_brace', (s.match(/{/g)||[]).length, 'close_brace', (s.match(/}/g)||[]).length);
console.log('open_sq', (s.match(/\[/g)||[]).length, 'close_sq', (s.match(/\]/g)||[]).length);
