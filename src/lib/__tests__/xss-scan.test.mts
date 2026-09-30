// Raw-HTML rendering (XSS) detection in the repo scan. Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkXss, findXssSinks, xssCandidatePaths } from "../xss-scan.ts";

test("candidates: UI files first, build output / tests / shadcn chart skipped, capped", () => {
  const { pick, total } = xssCandidatePaths(
    [
      "src/lib/api.ts",
      "src/routes/index.tsx",
      "dist/assets/index.js",
      "node_modules/x/index.js",
      "src/components/ui/chart.tsx",
      "src/App.test.tsx",
      "README.md",
      "src/components/Post.vue",
    ],
    2,
  );
  assert.equal(total, 3);
  assert.deepEqual(pick, ["src/routes/index.tsx", "src/components/Post.vue"]);
});

test("sinks: dynamic HTML flagged, string literals ignored, sanitiser recognised", () => {
  const unsafe = findXssSinks("a.tsx", `<div dangerouslySetInnerHTML={{ __html: post.body }} />`);
  assert.equal(unsafe.length, 1);
  assert.equal(unsafe[0].sanitized, false);
  assert.equal(unsafe[0].line, 1);

  assert.equal(findXssSinks("b.tsx", `<style dangerouslySetInnerHTML={{ __html: "body{margin:0}" }} />`).length, 0);

  const safe = findXssSinks("c.tsx", `import DOMPurify from "dompurify";\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />`);
  assert.equal(safe.length, 1);
  assert.equal(safe[0].sanitized, true);
  assert.equal(safe[0].line, 2);

  assert.equal(findXssSinks("d.ts", `el.innerHTML = userInput;`)[0].sink, "innerHTML/outerHTML assignment");
  assert.equal(findXssSinks("d.ts", `if (el.innerHTML === "") {}`).length, 0);
  assert.equal(findXssSinks("d.ts", `el.innerHTML = '';`).length, 0);
  assert.equal(findXssSinks("e.vue", `<div v-html="message"></div>`).length, 1);
  assert.equal(findXssSinks("f.svelte", `{@html content}`).length, 1);
  assert.equal(findXssSinks("g.ts", "el.insertAdjacentHTML('beforeend', `<li>${name}</li>`)").length, 1);
});

test("verdict: unsafe fails; none with full coverage passes; partial coverage is inconclusive", () => {
  const hit = findXssSinks("a.tsx", `<div dangerouslySetInnerHTML={{ __html: md }} />`);
  assert.equal(checkXss(hit, { scanned: 10, total: 10, failed: 0 }).status, "fail");
  assert.equal(checkXss([], { scanned: 10, total: 10, failed: 0 }).status, "pass");
  assert.equal(checkXss([], { scanned: 9, total: 10, failed: 1 }).status, "inconclusive");
  assert.equal(checkXss([], { scanned: 150, total: 400, failed: 0 }).status, "inconclusive");
  const sanitized = findXssSinks("c.tsx", `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(x) }} />`);
  assert.equal(checkXss(sanitized, { scanned: 1, total: 1, failed: 0 }).status, "pass");
});
