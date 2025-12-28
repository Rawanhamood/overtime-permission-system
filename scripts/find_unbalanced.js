const fs=require('fs');
const s=fs.readFileSync('backend/server.js','utf8');
let paren=0, brace=0, sq=0; 
const lines=s.split(/\r?\n/);
for(let i=0;i<lines.length;i++){
  const line=lines[i];
  for(let j=0;j<line.length;j++){
    const ch=line[j];
    if(ch==='(') paren++;
    else if(ch===')') paren--;
    if(ch==='{') brace++;
    else if(ch==='}') brace--;
    if(ch==='[') sq++;
    else if(ch===']') sq--;
    if(paren<0||brace<0||sq<0){
      console.log('Unbalanced close at', 'line', i+1, 'col', j+1, 'char', ch);
      process.exit(0);
    }
  }
}
console.log('Done. Remaining: paren',paren,'brace',brace,'sq',sq);
for(let i=0;i<30;i++) console.log(lines[lines.length-30+i]);
