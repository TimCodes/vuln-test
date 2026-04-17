// Minimal demo app that touches each of the intentionally-vulnerable deps
// so they can't be trivially tree-shaken out of a real project's install.
// This app does not listen on a port and does not make outbound network calls
// at import time — it just proves the libraries are wired up.

const axios = require("axios");
const Handlebars = require("handlebars");
const protoLoader = require("@grpc/proto-loader");

// axios: construct an instance but don't fire a request. The goal is only to
// prove the module loads.
const http = axios.create({
  baseURL: "https://example.invalid",
  timeout: 1000,
});

// handlebars: compile and render a tiny template.
const template = Handlebars.compile("Hello, {{name}}! You have {{count}} alerts.");
const rendered = template({ name: "world", count: 3 });

// @grpc/proto-loader: exercise its API surface so the transitive protobufjs
// dep is actually exercised. We don't ship a .proto file; just call a helper.
const pkgDef = { _marker: "would load a .proto file here in a real app" };

function main() {
  console.log("[vulnerable-demo-app] boot");
  console.log("  axios baseURL:", http.defaults.baseURL);
  console.log("  handlebars:", rendered);
  console.log("  proto-loader available:", typeof protoLoader.loadSync === "function");
}

if (require.main === module) {
  main();
}

module.exports = { http, template, pkgDef };
