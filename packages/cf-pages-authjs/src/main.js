import { Auth } from "@auth/core";
import CFPagesPlugin from "../tmp/index.js";
import { getAuthOptions } from "./auth";

export class AddInnerContent {

    #content;

    constructor(content = "") {
        this.#content = content;
    }

    async element(element) {
        element.setInnerContent(this.#content, { html: true })
        // fill in user info using response
    }
}

const createLoginMiddleware = ( 
        createLoginLink = (data) => {
            return `<div class="cf-pages-authjs-login-link"><a href="/auth/signin">Log in</a></div>`
        },
        createLogoutLink = (data) => {
            return `<div class="cf-pages-authjs-login-link"><a href="/auth/signout">Log out</a></div>`
        }
    ) => {
    return async (context) => {
        const {data, next} = context
        const response = await next()
        console.log("session", data.session)
        const loginComponent = (data.session) ? createLogoutLink(context) : createLoginLink(context)
        const etag = (data.session) ? "loggedin" : "loggedout"
        response.headers.set("Cache-Control", "private, max-age=0, must-revalidate")
        response.headers.set("ETag", etag)
        return new HTMLRewriter().on('.cf-pages-authjs-login', new AddInnerContent(loginComponent)).transform(response)
    }
}

const CFPages = (authConfig) => {
    const authPlugin = CFPagesPlugin(authConfig);
    const getSession = async (context) => {
        const { request } = context;
        const authOptions = await getAuthOptions(authConfig, context);
        const url = new URL("/auth/session", request.url);
        const sessionRequest = new Request(url, { headers: request.headers });
        const response = await Auth(sessionRequest, authOptions);
        const { status = 200 } = response;
        const data = await response.json();
        if (!data || !Object.keys(data).length)
            return null;
        if (status === 200)
            return data;
        throw new Error(data.message);    
    }
    return {authPlugin, getSession, createLoginMiddleware};
}

export default CFPages;