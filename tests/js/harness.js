// Runs one n8n Code node from workflows/src/ outside n8n, with just enough of the
// n8n globals ($env, $input, $(), $getWorkflowStaticData) for unit tests.
// This is not n8n: the end-to-end test (tests/e2e/) covers the real thing.
'use strict';
const fs = require('node:fs');
const path = require('node:path');

const SRC = path.join(__dirname, '..', '..', 'workflows', 'src', 'wazuh-ai-triage');
const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor;

function loadNode(name) {
  const code = fs.readFileSync(path.join(SRC, `${name}.js`), 'utf8');
  return new AsyncFunction('$env', '$input', '$', '$getWorkflowStaticData', code);
}

// mode "all": items is a list of item json objects. mode "each": one item json.
async function runNode(name, { env = {}, items = [], item, nodes = {}, staticData = {} } = {}) {
  const fn = loadNode(name);
  const wrap = (json) => ({ json });
  const $input = {
    all: () => items.map(wrap),
    item: item === undefined ? undefined : wrap(item),
  };
  const $ = (nodeName) => {
    if (!(nodeName in nodes)) throw new Error(`test did not provide node "${nodeName}"`);
    return { item: wrap(nodes[nodeName]) };
  };
  return fn(env, $input, $, () => staticData);
}

module.exports = { runNode, loadNode };
