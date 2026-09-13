// Static-analysis fixtures only; never executed.
const cp = require("child_process");
const fs = require("fs");
const DOMPurify = require("dompurify");

function unsafeShell(req) {
  const command = "echo " + req.query.text;
  // ruleid: dede.javascript.taint.command-injection
  cp.exec(command);
}

function safeShell(req) {
  // ok: dede.javascript.taint.command-injection
  cp.execFile("echo", [req.query.text]);
}

function unsafeSql(req, db) {
  const query = "SELECT * FROM users WHERE name = '" + req.body.name + "'";
  // ruleid: dede.javascript.taint.sql-injection
  db.query(query);
}

function safeSql(req, db) {
  // ok: dede.javascript.taint.sql-injection
  db.query("SELECT * FROM users WHERE name = ?", [req.body.name]);
}

function unsafeHtml(req, res) {
  const html = "<h1>" + req.query.name + "</h1>";
  // ruleid: dede.javascript.taint.xss
  res.send(html);
}

function safeHtml(req, res) {
  const html = DOMPurify.sanitize(req.query.name);
  // ok: dede.javascript.taint.xss
  res.send(html);
}

function lateSanitization(req, res) {
  // ruleid: dede.javascript.taint.xss
  DOMPurify.sanitize(res.send(req.query.name));
}

function safeInlineHtml(req, res) {
  // ok: dede.javascript.taint.xss
  res.send(DOMPurify.sanitize(req.query.name));
}

function lateNestedSanitization(req, res) {
  // ruleid: dede.javascript.taint.xss
  DOMPurify.sanitize(String(res.end(req.query.name)));
}

function lateElementSanitization(req, element) {
  // ruleid: dede.javascript.taint.xss
  DOMPurify.sanitize(element.innerHTML = req.query.name);
}

function unsafePath(req) {
  const path = "/uploads/" + req.params.file;
  // ruleid: dede.javascript.taint.path-traversal
  return fs.readFileSync(path);
}

function safePath(req) {
  // ok: dede.javascript.taint.path-traversal
  return fs.readFileSync("/uploads/constant.txt");
}

function unsafeRequest(req) {
  const url = req.query.url;
  // ruleid: dede.javascript.taint.ssrf
  return fetch(url);
}

function safeRequest(req) {
  // ok: dede.javascript.taint.ssrf
  return fetch("https://example.invalid/search", {body: req.body.query});
}
