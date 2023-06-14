export const actions = [
    "providers",
    "session",
    "csrf",
    "signin",
    "signout",
    "callback",
    "verify-request",
    "error",
];

export const getAuthOptions = async (paramAuthOptions, context) => {
    const authOptions = typeof paramAuthOptions === "object"
        ? paramAuthOptions
        : await paramAuthOptions(context);
    authOptions.secret ??= context.env.AUTH_SECRET;
    authOptions.trustHost ??= context.env.xxx;
    return authOptions;
}

