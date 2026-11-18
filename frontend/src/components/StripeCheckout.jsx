// Embedded Stripe Checkout. Nothing in the console imports this while card checkout is
// closed (backend/app/billing.py). The customer portal is a redirect, not this form.
// Kept so a future protected-user price can mount it again without re-learning the
// loading bug below.
//
// The import is "@stripe/stripe-js/pure", not "@stripe/stripe-js", and that is the whole
// difference between this file's lazy-loading claim being true and being aspirational.
// The default entrypoint injects js.stripe.com as an import side effect, for Stripe's
// fraud signals. Settings used to import this component at module scope and App imports
// Settings, so that side effect ran on every console screen at boot: Findings, Audit,
// Help, all of them, for every user, whether or not anyone ever opened billing. On a
// deployment with no self-serve billing the CSP correctly omits js.stripe.com (see
// main.py), so the blocked load logged a console error on all seventeen screens.
//
// /pure defers the script to the first loadStripe() call, which happens here, which only
// renders once a buyer has started checkout. Stripe's fraud detection is narrower as a
// result; that is the documented tradeoff and the right side of it for a security product
// that tells customers what leaves their machines.
import { useMemo } from "react";
import { loadStripe } from "@stripe/stripe-js/pure";
import { EmbeddedCheckoutProvider, EmbeddedCheckout } from "@stripe/react-stripe-js";

export default function StripeCheckout({ publishableKey, clientSecret }) {
  // loadStripe returns a promise; memoize so a re-render doesn't reload Stripe.js.
  const stripePromise = useMemo(() => loadStripe(publishableKey), [publishableKey]);
  return (
    <div className="stripe-embed">
      <EmbeddedCheckoutProvider stripe={stripePromise} options={{ clientSecret }}>
        <EmbeddedCheckout />
      </EmbeddedCheckoutProvider>
    </div>
  );
}
