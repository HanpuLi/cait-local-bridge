# Third-Party Notices

Cait Local Bridge is an original implementation that incorporates design lessons from several open-source projects. No upstream repository is vendored wholesale in the public export.

## DarwinRelay

Project: `dcierra/DarwinRelay`
License: MIT

The semantic macOS UI layer was informed by DarwinRelay's Accessibility-first architecture, fingerprinted element references, stale-reference handling, preconditions/postconditions, and explicit warning that event-delivery success is not equivalent to UI-state success.

The bridge implementation is Python/PyObjC and retains its own workspace/grant/audit model.

## Open Computer Use

Project: `opensymph/open-computer-use`
License: MIT

Open Computer Use informed the Accessibility-first/background-first desktop-control approach. It may be installed separately as an optional local runtime; it is not vendored or required by the core bridge.

## Shellby MCP

Project: `serbyte-development/shellby-mcp`
License: MIT

Shellby's named persistent-shell UX informed the persistent shell abstraction. The bridge implementation reuses its existing job/process-policy substrate rather than embedding Shellby.

## Microsoft Playwright MCP

Project: `microsoft/playwright-mcp`
License: Apache-2.0

Playwright MCP informed the preference for Accessibility-oriented browser state and attaching to an already-running browser/profile when appropriate. Cait Local Bridge uses Playwright directly and provides its own loopback-CDP attachment semantics.

## Computer Use MCP

Project: `onixhdz/computer-use-mcp`
License: MIT

Computer Use MCP informed the idea of returning a bounded, high-signal before/after Accessibility-state diff after desktop mutations. Cait Local Bridge independently implements this over its own PyObjC AX tree, fingerprint refs, grants and observation model; no upstream source file is vendored.

See the upstream repositories for their complete license texts and notices.
