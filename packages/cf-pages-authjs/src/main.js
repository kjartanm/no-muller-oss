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
            return `<a class="cf-pages-authjs-login-link" href="/auth/signin">Log in</a>`
        },
        createLogoutLink = (data) => {
            return `<a class="cf-pages-authjs-login-link" href="/auth/signout">Log out</a>`
        }
    ) => {
    return async (context) => {
        const {data, next} = context
        const response = await next()
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
        const session = await response.json();
        if (!session || !Object.keys(session).length){
            return null;
        }
        if (status === 200 || status === 302){
            return session;
        }
        throw new Error(session.message);    
    }
    const setSession = async (context) => {
        const session = await getSession(context);
        if(session){
            context.data.session = session;
        }
        return context.next();
    }
    return {authPlugin, getSession, setSession, createLoginMiddleware};
}

export default CFPages;