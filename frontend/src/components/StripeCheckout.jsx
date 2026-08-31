// Embedded Stripe Checkout — Stripe's prebuilt card form mounted on our own page, so the
// buyer never leaves the console. Stripe.js is loaded lazily (only when a checkout starts)
// and memoized per publishable key; the client secret comes from our backend's
// /api/billing/checkout (ui_mode=embedded). On completion Stripe returns to
// /#billing=success on our domain, and the webhook flips the plan.
import { useMemo } from "react";
import { loadStripe } from "@stripe/stripe-js";
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
