import { z } from 'zod';


// ------------------------------------------------------------
// Request schemas
// ------------------------------------------------------------

export const userSchema = z.object({
    name: z.string().min(1),
    email: z.email(),
}).strict(); // --> use strict() if the rq body must match exactly the schema. remove strict() if at least the required keys must be present in the body