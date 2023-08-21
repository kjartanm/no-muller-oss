# Authjs plugin for Cloudflare Pages

This plugin lets you use Auth.js (https://authjs.dev/) together with Cloudflare Pages for authentication. You can already use Auth.js with Next.js, Solid or SvelteKit -- which all is supported by Cloudflare Pages directly, but if you for example want to add authentication to a single page application or some static site built by SSG (like Eleventy), then this plugin will help you do that.

How to install:

`npm i @kjartanm/cf-pages-authjs`

## How to use:
You initialize the plugin by providing a config object or config function, according to Auth.js documentation, then add it as middleware in your pages application.

```
# functions/_middleware.js
import CFPagesAuth from "@kjartanm/cf-pages-authjs";
import GitHub from "@auth/core/providers/github";

const { authPlugin } = CFPagesAuth({
  providers: [GitHub({ clientId: GITHUB_ID, clientSecret: GITHUB_SECRET })],
});

export const onRequest = [authPlugin];
```

You can also use a function as config argument:

```
const { authPlugin } = CFPagesAuth(
    ({ env }) => {
        return { providers: [GitHub({ clientId: env.GITHUB_ID, clientSecret: env.GITHUB_SECRET })],}
});
```
The plugin also exports additional methods and middleware that can be used. `getSession`can be used to get session info, `setSession` adds session object to context.data, and this again can be used for authorizing different routes:

```
# functions/_middleware.js

const {authPlugin, getSession, setSession } = CFPagesAuth(authConfig);

const doSomethingWithSession = async (context) => {
    const session = await getSession(context);

    ...

    return context.next();
}

export const onRequest = [authPlugin, doSomethingWithSession, setSession];

#####

# functions/protected/_middleware.js

const protectRoute = async ({ next, data }) => {
    if (!data.session) {
        return new Response("No access", { status: 401 })
    }
    return next();
}

export const onRequest = [protectRoute];
```

It also exports middleware to add login-form to your app based on HTMLWriter (it reqires that `data.session` is set). 

```
const { authPlugin, setSession, createLoginMiddleware } = CFPagesAuth(getAuthConfig);


const addLoginComponent = createLoginMiddleware(
    ({env}) => {
        return `<div class="cf-pages-authjs-login-link"><a href="/auth/signin?callbackUrl=${env.CALLBACK_URL}">Log in</a></div>`
    },
    ({data}) => {
        return `
        <div>${ data.session.user.name }</div>
        <div class="cf-pages-authjs-login-link"><a href="/auth/signout">Log out</a></div>`
    }
);

export const onRequest = [authPlugin, setSession, addLoginComponent];

```