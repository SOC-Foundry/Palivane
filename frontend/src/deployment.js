// Which deployment this build IS, decided at build time by VITE_PALIVANE_SELF_HOSTED (see
// deploy/cloudrun/Dockerfile).
//
// It exists for one reason: the marketing pages promise something about where a customer's
// prompt text ends up, and the honest answer is not the same in both cases. Self-hosted,
// the text never leaves the operator's own infrastructure. On the managed service it
// reaches Palivane, which by default keeps the verdict and discards the text. Stating both
// every time is accurate but reads as hedging, and the reader has to work out which half
// applies to them.
//
// Build time rather than a /api/health fetch: this decides prose above the fold, and a page
// that renders one data-handling promise and then swaps it for another is worse than either
// promise alone. It is also fixed for the life of an image, so there is nothing to fetch.
//
// The polarity is deliberate. "Never leaves your infrastructure" is the STRONGER claim, so
// it is the one you opt into; an unset flag anywhere yields the managed copy. Every way of
// getting this wrong then UNDERSTATES the guarantee, which costs a little marketing punch.
// The other polarity would let a forgotten variable on the managed service tell customers
// their prompts never reach us, which is the failure that actually matters. docker-compose
// sets it, so the ordinary self-host path still says the true, stronger thing.
export const SELF_HOSTED = import.meta.env.VITE_PALIVANE_SELF_HOSTED === "1";
