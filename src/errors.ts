/** Errors with a stable code, for --json output, MCP and HTTP status mapping. */
export class ApiError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}
