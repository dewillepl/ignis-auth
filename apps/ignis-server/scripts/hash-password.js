// Generates the bcrypt hash for AUTH_PASSWORD_HASH.
//
//   npm run auth:hash                 prompts, nothing lands in shell history
//   npm run auth:hash -- 'password'   non-interactive
//   npm run auth:hash -- --rounds 12  cost factor (default 12)

const bcrypt = require("bcryptjs");
const readline = require("readline");

const args = process.argv.slice(2);
let rounds = 12;
const positional = [];

for (let i = 0; i < args.length; i++) {
  if (args[i] === "--rounds" || args[i] === "-r") {
    rounds = parseInt(args[++i], 10);
    continue;
  }

  positional.push(args[i]);
}

if (!Number.isInteger(rounds) || rounds < 8 || rounds > 15) {
  console.error("[auth:hash] --rounds must be between 8 and 15");
  process.exit(1);
}

// Reads a password without echoing it back to the terminal.
function prompt(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true,
    });

    const onData = (char) => {
      if (String(char) === "\n" || String(char) === "\r") {
        process.stdin.removeListener("data", onData);
        return;
      }

      readline.clearLine(process.stdout, 0);
      readline.cursorTo(process.stdout, 0);
      process.stdout.write(question);
    };

    process.stdout.write(question);
    process.stdin.on("data", onData);

    rl.question("", (answer) => {
      rl.close();
      process.stdout.write("\n");
      resolve(answer);
    });
  });
}

async function main() {
  let password = positional[0];

  if (!password) {
    if (!process.stdin.isTTY) {
      console.error(
        "[auth:hash] usage: npm run auth:hash -- 'password'  (or run it in a terminal to be prompted)",
      );
      process.exit(1);
    }

    password = await prompt("Password: ");
    const again = await prompt("Repeat: ");

    if (password !== again) {
      console.error("[auth:hash] passwords do not match");
      process.exit(1);
    }
  }

  if (!password) {
    console.error("[auth:hash] empty password");
    process.exit(1);
  }

  if (Buffer.byteLength(password, "utf-8") > 72) {
    console.warn(
      "[auth:hash] WARNING: bcrypt only uses the first 72 bytes of the password",
    );
  }

  const hash = await bcrypt.hash(password, rounds);

  // docker-compose reads a single "$" in .env as an interpolation marker and would mangle the
  // hash, so the .env line carries every "$" doubled. The server accepts either form.
  const escaped = hash.replace(/\$/g, "$$$$");

  console.log("");
  console.log("hash:            " + hash);
  console.log("");
  console.log("Add to .env (dollars doubled for docker-compose):");
  console.log("");
  console.log("AUTH_PASSWORD_HASH=" + escaped);
  console.log("");
}

main().catch((e) => {
  console.error("[auth:hash]", e.message);
  process.exit(1);
});
