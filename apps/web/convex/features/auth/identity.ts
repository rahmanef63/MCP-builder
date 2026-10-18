import { v } from "convex/values"
import { query } from "../../_generated/server"
import { requireUser } from "../../_shared/auth"

/** The caller's own identity, used to bind an OAuth round trip to its owner. */
export const currentUserId = query({
  args: {},
  returns: v.id("users"),
  handler: async (ctx) => await requireUser(ctx),
})
