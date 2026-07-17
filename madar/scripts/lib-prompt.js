// Robust terminal prompts for operator scripts.
// Hidden input uses raw mode directly (works under `docker compose exec -it`,
// macOS Terminal, iTerm, Linux ttys) — no fragile readline monkey-patching.
const readline = require('readline');

function askVisible(question) {
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, a => { rl.close(); resolve(a.trim()); });
  });
}

function askHidden(question) {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) {
      return reject(new Error('No TTY for hidden input — run with `docker compose exec -it` or pass the value via environment variable.'));
    }
    process.stdout.write(question);
    const stdin = process.stdin;
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8');
    let value = '';
    const onData = (ch) => {
      for (const c of ch) {
        if (c === '\r' || c === '\n') {
          stdin.setRawMode(false); stdin.pause(); stdin.removeListener('data', onData);
          process.stdout.write('\n');
          return resolve(value);
        }
        if (c === '') { // Ctrl-C
          stdin.setRawMode(false); process.stdout.write('\n');
          return reject(new Error('cancelled'));
        }
        if (c === '' || c === '\b') { value = value.slice(0, -1); continue; }
        value += c;
      }
    };
    stdin.on('data', onData);
  });
}

// Hidden prompt with mandatory confirmation — catches typos and any capture
// mismatch before anything is stored.
async function askHiddenConfirmed(label, minLen = 12) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const first = await askHidden(`${label} (${minLen}+ chars, hidden): `);
    if (first.length < minLen) { console.error(`Too short (min ${minLen}) — try again.`); continue; }
    const second = await askHidden('Re-enter to confirm: ');
    if (first === second) return first;
    console.error('Values do not match — try again.');
  }
  throw new Error('Confirmation failed three times.');
}

module.exports = { askVisible, askHidden, askHiddenConfirmed };
