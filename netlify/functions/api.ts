import { handle } from "hono/netlify";
import app from "../../src/worker";

export const handler = handle(app);
