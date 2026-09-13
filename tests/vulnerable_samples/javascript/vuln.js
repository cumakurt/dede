// Intentionally vulnerable JavaScript samples for Dede tests.
// Secrets are FAKE / EXAMPLE values only.

function runUserCode(userInput) {
  // FAKE vulnerability: code injection
  return eval(userInput);
}

function insecureExec(userInput) {
  const { exec } = require("child_process");
  // FAKE vulnerability: command injection
  exec("echo " + userInput);
}

const apiKey = "FAKESECRET_e4f5g6h7i8j9k0l1m2n3"; // FAKE

module.exports = { runUserCode, insecureExec, apiKey };
