# gramberry

This is a WIP twilio frontend.

## Local Development

tl;dr if you don't want to read this whole section, you can just:
```shell
npm start
```
- starts `cargo watch ...`
- starts `npx tailwindcss ... --watch`

### Backend Changes

If you're iterating on backend behavior that tests
real HTTP or something else like that, I've been
using this to keep the rust compilation going:

```shell
RUST_LOG=debug cargo watch -x run --ignore public
```

- :notebook: If you get tired of your login/cookies getting wiped
  on each recompile, you can set `GRAMBERRY_SECRET` somewhere.
  If you need a random secret, you can steal my command if you have
  `sha256sum`:
  ```
  head /dev/random | sha256sum | sed -rn "s/ +.*$//p"
  ```
- `RUST_LOG=debug` causes lots of logging to occur, which I like.
  It helped me discover that my HTTP connections were not getting
  reused in early iterations, for example.

### Frontend Changes

Template HTML changes are compiled by the rust command above,
but if you are changing the tailwind classes/styles (in HTML,
or in `tailwind.css`), then you'll want a live tailwindcss command
consuming those changes and spitting out an updated `public/styles.css`
file:

```shell
npx tailwindcss -i public/tailwind.css \
  --config public/tailwind.config.js \
  -o public/styles.css \
  --watch
```
