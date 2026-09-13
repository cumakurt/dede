// Static-only security regression samples; never execute this module.
const ejs = require("ejs");
const serialize = require("node-serialize");
const jwt = require("jsonwebtoken");
const https = require("https");
const vm = require("vm");
import serializer from "node-serialize";
import * as tokens from "jsonwebtoken";

function documentQueries(req, users, db) {
  const filter = req.body;
  // ruleid: dede.javascript.web.nosql-injection
  users.findOne(filter);
  // ruleid: dede.javascript.web.nosql-injection
  users.findOne({name: req.body.name});
  // ruleid: dede.javascript.web.nosql-injection
  db.collection("users").find(filter);
  // ok: dede.javascript.web.nosql-injection
  users.findOne({name: String(req.body.name)});
  // ok: dede.javascript.web.nosql-injection
  users.findOne({name: "fixed"});
  // ruleid: dede.javascript.web.nosql-injection
  String(users.findOne(filter));
  // ruleid: dede.javascript.web.nosql-injection
  users.findOne({name: String(req.body.name), role: req.body.role});
}

function nestedProperties(req, target) {
  const key = req.body.key;
  // ruleid: dede.javascript.web.prototype-pollution
  target[key]["admin"] = true;
  // ok: dede.javascript.web.prototype-pollution
  target["settings"]["theme"] = req.body.theme;
}

function evaluation(req) {
  const code = req.query.code;
  // ruleid: dede.javascript.web.code-injection
  eval(code);
  // ruleid: dede.javascript.web.code-injection
  new Function(code);
  // ruleid: dede.javascript.web.code-injection
  new Function("name", code);
  // ruleid: dede.javascript.web.code-injection
  vm.runInNewContext(code, {});
  // ok: dede.javascript.web.code-injection
  eval("1 + 2");
}

function redirects(req, res) {
  const destination = req.query.next;
  // ruleid: dede.javascript.web.open-redirect
  res.redirect(destination);
  // ruleid: dede.javascript.web.open-redirect
  res.redirect(302, destination);
  // ok: dede.javascript.web.open-redirect
  res.redirect("/dashboard");
}

function templates(req) {
  const template = req.body.template;
  // ruleid: dede.javascript.web.template-injection
  ejs.render(template, {});
  // ok: dede.javascript.web.template-injection
  ejs.render("Hello <%= name %>", {name: template});
}

function deserialization(req) {
  const payload = req.body.serialized;
  // ruleid: dede.javascript.web.unsafe-deserialization
  serialize.unserialize(payload);
  // ruleid: dede.javascript.web.unsafe-deserialization
  serializer.unserialize(payload);
  // ruleid: dede.javascript.web.unsafe-deserialization
  require("node-serialize").unserialize(payload);
  // ok: dede.javascript.web.unsafe-deserialization
  JSON.parse(payload);
}

function tokenVerification(token, key) {
  // ruleid: dede.javascript.web.jwt-none-algorithm
  jwt.verify(token, key, {algorithms: ["HS256", "none"]});
  // ruleid: dede.javascript.web.jwt-none-algorithm
  tokens.verify(token, key, {algorithms: ["none"]});
  // ruleid: dede.javascript.web.jwt-none-algorithm
  require("jsonwebtoken").verify(token, key, {algorithms: ["none"]});
  // ok: dede.javascript.web.jwt-none-algorithm
  jwt.verify(token, key, {algorithms: ["HS256"]});
}

function tlsSettings() {
  // ruleid: dede.javascript.web.tls-verification-disabled
  new https.Agent({rejectUnauthorized: false});
  // ok: dede.javascript.web.tls-verification-disabled
  new https.Agent({rejectUnauthorized: true});
}

function unrelatedLibraries(req, customSerializer, customTokens) {
  // ok: dede.javascript.web.unsafe-deserialization
  customSerializer.unserialize(req.body.serialized);
  // ok: dede.javascript.web.jwt-none-algorithm
  customTokens.verify("token", "key", {algorithms: ["none"]});
}
