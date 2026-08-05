// Host-side JS implementation of polymorph:test/test-context@0.1.0
// (the jco analog of the context provider: the runner is the provider).
export class Context {
  constructor(onDiagnostic) {
    this.onDiagnostic = onDiagnostic ?? (() => {});
  }
  async diagnostic(msg) {
    this.onDiagnostic(msg);
  }
}
