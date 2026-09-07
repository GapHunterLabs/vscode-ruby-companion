# Ruby Companion (VS Code)

3 turnkey Ruby checks, live in the editor — no configuration, no data
leaves your editor.

**v0.1, pilot.** Part of the Gap Hunter Labs VS Code workstream. This
combines 3 IntelliJ-family plugins (`ruby-shell-injection-companion`,
`ruby-nethttp-reuse-companion`, `ruby-gemfile-group-companion`) into
one extension, same reasoning as PHP Security Companion: one listing
with several rules fits VS Code better than 3 tiny near-duplicate
ones.

## What it checks

| Rule | Applies to | Flags |
|---|---|---|
| `shell-injection` | `.rb` files | `system(`/`exec(`/backticks/`%x[]` built with `#{}` interpolation instead of the safe array-argument form |
| `nethttp-per-iteration` | `.rb` files | `Net::HTTP.get`/`.get_response`/`.post` (opens+closes a connection every call) found inside a loop/iterator block — use `Net::HTTP.start(...)` to reuse one connection |
| `ungrouped-dev-test-gem` | `Gemfile` | A well-known dev/test gem (rspec, pry, byebug, factory_bot, capybara, rubocop, brakeman, ...) declared outside any `group :development, :test do` block — it ships in every environment, including production |

**v0.1 scope, honestly noted (same as the IntelliJ-family originals):**
plain-text/regex matching against loop and block headers, not a real
Ruby parser — an unusual loop or block shape not matching the common
patterns (`.each do`, `while`, brace blocks, `group ... do`) isn't
specially tracked.

## Privacy

See [PRIVACY.md](PRIVACY.md) — zero network calls, everything runs
against files already open in your editor.

## Development

```bash
npm install
npm run compile   # or: npm run watch
npm test
```

Press F5 (with this folder open) to launch an Extension Development
Host against a real `.rb` file or `Gemfile`. To build an installable
package without publishing:

```bash
npx @vscode/vsce package
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
