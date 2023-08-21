# Feide as provider for Authjs

This adds Feide (https://www.feide.no/) to the list of providers for Authjs (https://authjs.dev/)

## How to install:

`npm i @kjartanm/feide-authjs`

## Setup

### Callback URL

```
https://example.com/api/auth/callback/github
```

### Configuration

```js
import { Auth } from "@auth/core";
import Feide from "@kjartanm/feide-authjs";

const request = new Request(origin);
const response = await Auth(request, {
    providers: [
        Feide({
            clientId: env.FEIDE_ID,
            clientSecret: env.FEIDE_SECRET,
        }),
    ],
    session: {
        maxAge: 27000,
    },
});
```

See documentation for how to use the Feide-provider with frameworks like Next.js, SvelteKit and SolidStart:

https://authjs.dev/


### Group information

If you for example want to add group information from the core API to the session, you need to make sure the access token is available:

```js
import { Auth } from "@auth/core";
import Feide from "@kjartanm/feide-authjs";

const request = new Request(origin);
const response = await Auth(request, {
    providers: [
        Feide({
            clientId: env.FEIDE_ID,
            clientSecret: env.FEIDE_SECRET,
        }),
    ],
    session: {
        maxAge: 27000,
    },
    callbacks: {
        async jwt({ token, account }) {
            if (account) {
                token.access_token = account.access_token
            }
            return token
        },
        async session({ session, token }) {
            if (token.access_token) {
                const groups = await fetch("https://groups-api.dataporten.no/groups/me/groups", {
                    headers: { Authorization: `Bearer ${token.access_token}` },
                }).then(async (res) => await res.json());
                session.access_token = token.access_token
                session.groups = groups
            }
            return session
        }
    },
});
```

