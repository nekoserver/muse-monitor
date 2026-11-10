// Minimal stand-in for the DurableObject base class from cloudflare:workers.
export class DurableObject<Env = unknown> {
  constructor(protected ctx: DurableObjectState, protected env: Env) {}
}
