# Watch a session live

Obscura is headless, so a page it renders is invisible unless you ask for it. This guide builds a small live viewer on top of `obscura serve`: it opens its own page, navigates it, and streams what the browser paints to a local tab. It uses only Node's built-in modules and its native WebSocket client (Node 21+).

## What this can and cannot show

The viewer watches **the page it owns**, not a page another client created.

`obscura serve` gives every WebSocket connection its own isolated `CdpContext`, and a page belongs to the context of the socket that created it. So `Target.getTargets` reports only your own targets — correctly — and `Target.attachToTarget` on an id from another connection answers `Target not found`.

`/json/list` looks like a way around this and is not. It is a fixed discovery shim: its `id`, `title` and `url` are constants, so it reports `page-1` at `about:blank` whether or not such a page exists and wherever the real pages have navigated. Attaching to the `page-1` it names fails from any socket that did not create it.

Watching an agent's existing session would need a shared target registry across connections, which this server does not have. To see what an agent does, drive the same page from the viewer's own session instead.

## How it works

1. Start the CDP server:

```bash
obscura serve --port 9222
```

2. Run the viewer script below:

```bash
node watch.mjs 9222 8080 https://example.com
```

3. Open http://localhost:8080 in a browser. The page the viewer owns appears there, updating as it paints.

Pass a URL as the third argument to navigate that page:

```bash
node tools/live-view.mjs 9222 8080 https://example.com
```

The script creates a page target over CDP, captures it twice a second with `Page.captureScreenshot`, and forwards JPEG frames to your browser over Server-Sent Events.

```js
// watch.mjs
// Usage: node watch.mjs [cdpPort] [httpPort] [url]
import http from "node:http";

const cdpPort = process.argv[2] ?? 9222;
const httpPort = process.argv[3] ?? 8080;
const startUrl = process.argv[4] ?? null;

const clients = new Set();
let latest = null;
let sessionId = null;
let ws = null;

const page = `
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Obscura live</title>
<style>body{margin:0;background:#111;display:grid;place-items:center;height:100vh}
img{max-width:100%;max-height:100%}</style></head>
<body><img id="s" alt="live page">
<script>
const img = document.getElementById("s");
let old = null;
const es = new EventSource("/events");
es.onmessage = (e) => {
  const bytes = Uint8Array.from(atob(e.data), (c) => c.charCodeAt(0));
  const url = URL.createObjectURL(new Blob([bytes], { type: "image/jpeg" }));
  img.src = url;
  if (old) URL.revokeObjectURL(old);
  old = url;
};
</script></body>
</html>`;

const server = http.createServer((req, res) => {
  if (req.url === "/events") {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-store",
      Connection: "keep-alive",
    });
    res.socket.setNoDelay(true);
    if (latest) res.write(`data:${latest}\n\n`);
    clients.add(res);
    req.on("close", () => clients.delete(res));
  } else {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(page);
  }
});

server.listen(httpPort, "127.0.0.1", () => {
  console.log(`live view: http://localhost:${httpPort}`);
});

function broadcast(base64) {
  latest = base64;
  for (const res of clients) {
    if (res.writable) res.write(`data:${base64}\n\n`);
  }
}

async function connect() {
  ws = new WebSocket(`ws://127.0.0.1:${cdpPort}/devtools/browser`);
  let id = 0;
  const pending = new Map();
  const call = (method, params = {}, sess) =>
    new Promise((resolve, reject) => {
      const mid = ++id;
      pending.set(mid, { resolve, reject });
      const msg = { id: mid, method, params };
      if (sess) msg.sessionId = sess;
      ws.send(JSON.stringify(msg));
    });

  ws.addEventListener("message", (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const p = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    }
  });
  ws.addEventListener("close", () => {
    sessionId = null;
    setTimeout(() => connect().catch(retry), 2000);
  });
  ws.addEventListener("error", () => ws.close());

  await new Promise((resolve) => ws.addEventListener("open", resolve));

  // Reuse a target this socket already owns, if there is one. Only our own
  // targets are attachable -- a target belongs to the context of the socket
  // that created it.
  const { targetInfos } = await call("Target.getTargets");
  const existing = targetInfos.find((t) => t.type === "page");
  if (existing) {
    const attached = await call("Target.attachToTarget", {
      targetId: existing.targetId,
      flatten: true,
    });
    sessionId = attached.sessionId;
  } else {
    // A freshly created target is auto-attached under a managed session id.
    const created = await call("Target.createTarget", { url: "about:blank" });
    sessionId = `${created.targetId}-session`;
    if (startUrl) await call("Page.navigate", { url: startUrl }, sessionId);
  }
  await call("Page.enable", {}, sessionId);

  // capture on an interval instead of Page.startScreencast: screencast only
  // emits when the page paints something new, so an idle page goes dark. An
  // explicit capture always reflects the current page state.
  const capture = async () => {
    if (ws.readyState !== WebSocket.OPEN || !sessionId) return;
    try {
      const shot = await call(
        "Page.captureScreenshot",
        { format: "jpeg", quality: 70 },
        sessionId
      );
      if (shot.data && shot.data.length > 100) broadcast(shot.data);
    } catch {
      // transient failures during navigation are normal, retry next tick
    }
    setTimeout(capture, 500);
  };
  capture();
}

function retry(err) {
  console.error(err.message);
  sessionId = null;
  setTimeout(() => connect().catch(retry), 2000);
}
connect().catch(retry);
```


> For a packaged version with adaptive pacing (fast while painting, idle back-off) and reconnection handling, see `tools/live-view.mjs`.

## Things worth knowing

- **Why captureScreenshot polling instead of screencast.** `Page.startScreencast` only produces frames when the page paints something new, so a page that is merely sitting there goes dark. An explicit `Page.captureScreenshot` always reflects current state, which is what you want for a viewer.
- **Acknowledge every frame.** If you do use screencast, `Page.screencastFrameAck` is required or delivery stops after the first frame.
- **Targets are per-connection.** A target created on one WebSocket cannot be attached to from another; see the section above. `Target.createTarget` auto-attaches under the session id `{targetId}-session`, so a target you created needs no explicit attach.
- **Still images vs continuous view.** The MCP server exposes `browser_screenshot` for one-shot captures. Polling capture is the right tool when you want to watch continuously; it stays CDP-only by design.

## Verifying

With `obscura serve` running and the viewer open:

1. Start it with a URL: `node tools/live-view.mjs 9222 8080 https://example.com`.
2. The tab shows the page within a second of it painting.
3. Closing the viewer tab and reopening it resumes from the most recent frame.

Navigating from a *separate* client (a Puppeteer, Playwright or MCP session on the same port) will not appear here — that session owns its own page. See the scope note above.
