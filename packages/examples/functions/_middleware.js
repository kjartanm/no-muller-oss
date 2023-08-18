import CFPagesAuth from '@kjartanm/cf-pages-authjs'
import Credentials from "@auth/core/providers/credentials";

function getAuthConfig({ env }) {

    return {
        providers: [
            Credentials({
                credentials: {
                    username: { label: "Username" },
                    password: { label: "Password", type: "password" },
                },
                async authorize(creds, req) {
                    if (env.AUTH_USERNAME !== creds.username || env.AUTH_PWD !== creds.password) {
                        return null;
                    }
                    const user = {
                        id: creds.username,
                        email: creds.username,
                        date: Date.now(),
                    }
                    return user
                }
            })
        ],
        trustHost: true,
        session: {
            strategy: "jwt",
            maxAge: 2 * 3600, //two hours
        },
        callbacks: {
            async jwt({ token, profile, account }) {
                if (account) {
                    token.provider = account.provider;
                }
                return token;
            },

            async session({ session, token }) {
                session.provider = token.provider;
                return session
            }
        },
    }
}
const { authPlugin, getSession, createLoginMiddleware } = CFPagesAuth(getAuthConfig);

const setSession = async (context) => {
    const session = await getSession(context);
    if (session) {
        context.data.session = session;
    }
    return context.next();
}

const addLoginComponent = createLoginMiddleware(
    ({env}) => {
        return `<div class="cf-pages-authjs-login-link"><a href="/auth/signin?callbackUrl=${env.CALLBACK_URL}">Logg inn</a></div>`
    },
    ({data}) => {
        return `
        <div>${ data.session.user.email }</div>
        <div class="cf-pages-authjs-login-link"><a href="/auth/signout?callbackUrl=/test2">Logg ut</a></div>`
    }
);

export const onRequest = [authPlugin, setSession, addLoginComponent];