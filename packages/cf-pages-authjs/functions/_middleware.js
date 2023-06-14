import { Auth } from "@auth/core";
import { getAuthOptions, actions } from "../src/auth";

export const onRequest = async (context) => {
    const { next, request, pluginArgs } = context;
    const url = new URL(request.url);
    const authOptions = await getAuthOptions(pluginArgs, context);
    const { prefix = "/auth" } = authOptions;
    const action = url.pathname
        .slice(prefix.length + 1)
        .split("/")[0];
    if (!actions.includes(action) || !url.pathname.startsWith(prefix + "/")) {
        return next();
    }
    return Auth(request, authOptions);
}


