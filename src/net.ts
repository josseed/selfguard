/**
 * Response bodies read with a size cap. `res.text()` buffers the whole body before a cap can be
 * checked, so a server (or anything in between) streaming without end could fill memory. Here
 * the download stops as soon as it passes the cap.
 */

/** The body as UTF-8 text, or null (download stopped) once it is larger than `maxBytes`. */
export async function readCapped(res: Response, maxBytes: number): Promise<string | null> {
  if (Number(res.headers.get("content-length") ?? 0) > maxBytes) {
    await res.body?.cancel().catch(() => {});
    return null;
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  if (res.body) {
    for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
      size += chunk.byteLength;
      // Leaving the loop cancels the stream, which closes the connection.
      if (size > maxBytes) return null;
      chunks.push(chunk);
    }
  }
  // TextDecoder drops a leading BOM, like res.text().
  return new TextDecoder().decode(Buffer.concat(chunks));
}
