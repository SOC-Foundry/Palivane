// Email Routing fan-out for the palivane.io public addresses (sales@, support@,
// security@, privacy@, hello@ — one routing rule each): Cloudflare forward rules allow
// exactly one destination, so this worker forwards each inbound message to every
// founder. The original To: header survives forwarding, so recipients can filter
// support vs security in their own mailboxes.
// Destinations MUST be verified in Email Routing (Dashboard -> Email -> Destination
// addresses) or forward() rejects. One failed destination must not eat the lead, so
// failures are logged and the rest still go out; if NONE succeeded, throw so the
// sender gets a bounce instead of silent loss.
const DESTINATIONS = [
  "david@socfoundry.com",
  "dan@socfoundry.com",
  "kyle@socfoundry.com",
];

export default {
  async email(message, env, ctx) {
    const results = await Promise.allSettled(
      DESTINATIONS.map((to) => message.forward(to)),
    );
    const failed = results.filter((r) => r.status === "rejected");
    for (const f of failed) console.error("forward failed:", String(f.reason));
    if (failed.length === DESTINATIONS.length) {
      throw new Error("all forwards failed — bouncing so the sender knows");
    }
  },
};
